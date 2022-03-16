# Copyright (C) 2022
#     Authors: Pudii (2022), Csaba Barta (2015)
#  
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.

from volatility3.framework import interfaces, contexts, automagic, plugins, renderers, interfaces, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist, vadinfo

class Processbl(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    '''
    Scans memory for processes and loaded DLLs and compares the results with a provided baseline
    '''
    
    baseline_proc_list = {}
    image_proc_list = []
    image_mapped_files = {}

 
    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel', architectures = ["Intel32", "Intel64"]),
            requirements.VersionRequirement(name = 'pslist', component = pslist.PsList, version = (2, 0, 0)),
            requirements.VersionRequirement(name = 'pslist', component = vadinfo.VadInfo, version = (2, 0, 0)),
            requirements.URIRequirement(name = "baseline_img", description = "Baseline image", optional = False),
            requirements.BooleanRequirement(name = 'onlyknown', description = 'Display only the processes and dlls that can also be found in the baseline image', optional = True),
            requirements.BooleanRequirement(name = 'onlyunknown', description = 'Display only the processes and dlls that cannot be found in the baseline image', optional = True),
            requirements.BooleanRequirement(name = 'verbose', description = 'Print verbose output from where the dll is loaded', optional = True),
           ]


    def enrich_procobj_with_dll(self, proc, proc_obj, module_list: str):
        """Enrich process object with DLLs registered in the specified module list"""

        mod_list = []
        if module_list == "load":
            mod_list = proc.load_order_modules()
        elif module_list == "mem":
            mod_list = proc.mem_order_modules()
        elif module_list == "init":
            mod_list = proc.init_order_modules()

        for mod in mod_list:
            mod_obj = {
                'dll' : mod.FullDllName.get_string().lower(),
                'base' : mod.DllBase,
                'size' : mod.SizeOfImage or -1
            }
            
            # If module not in specified module list, add it
            if mod_obj['dll'] not in proc_obj['dlls'][module_list]:
                proc_obj['dlls'][module_list][mod_obj['dll']] = mod_obj
            
            # If module not in combined module list, add it
            if mod_obj['dll'] not in proc_obj['dlls']['comb']:
                proc_obj['dlls']['comb'][mod_obj['dll']] = mod_obj

        return proc_obj


    def add_missing_modules_vads(self, context, proc, pe_table_name, proc_layer_name, proc_obj):
        """Check the VADs of the process and add the missing modules"""

        def filter_function(x: interfaces.objects.ObjectInterface) -> bool:
            try:
                return not (x.get_private_memory() == 0 and x.ControlArea)
            except AttributeError:
                return False

        filter_func = filter_function
        for vad in vadinfo.VadInfo.list_vads(proc, filter_func = filter_func):              
            dos_header = context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                                offset = vad.get_start(),
                                layer_name = proc_layer_name)
            try:
                # Filter out VADs that do not start with a MZ header
                if dos_header.e_magic != 0x5A4D:
                    continue
            except exceptions.PagedInvalidAddressException:
                continue

            mod = {
                'dll' : str(vad.get_file_name() or '').lower(),
                'base': int(vad.get_start()),
                'size': int(vad.get_end() - vad.get_start())
            }

            # Add module to vad list if not existent already
            if mod['dll'] not in proc_obj['dlls']['vad']:
                proc_obj['dlls']['vad'][mod['dll']] = mod
            
            # Check if base address of module in combined list matches the base address of the module found by vad
            f = False
            for m in proc_obj['dlls']['comb']:
                if proc_obj['dlls']['comb'][m]['base'] == mod['base']:
                    f = True
            
            # If module found by vad is not in combined list, add it.
            if not f:
                proc_obj['dlls']['comb'][mod['dll']] = mod
        
        return proc_obj


    def _generator(self):
        # Check if both options are given which are complementary. Only one of them can be active.
        if self.config.get('onlyknown', None) and self.config.get('onlyunknown', None):
            print("Select only one of the options (--onlyknown, --onlyunknown)!")
            return -1
        

        ###############################################
        # Search for processes in the baseline image  #
        ###############################################
        
        # Set up context of baseline image
        bl_context = contexts.Context()

        # Get list of available AutmagicInterface subclasses
        automagics = automagic.available(bl_context)

        # Get file path of baseline image and set it in the config of the baseline context
        try:
            single_location = self.config.get("baseline_img", None)
            bl_context.config['automagic.LayerStacker.single_location'] = single_location
        except ValueError as excp:
            print("ERROR")

        # Generate PsList plugin object based on the baseline image/baseline context
        constructed = plugins.construct_plugin(bl_context, automagics, pslist.PsList, None, None, None)
 
        bl_kernel = constructed.context.modules[constructed.config['kernel']]

        # Create an intermediate symbol table for PE files from baseline memory image
        bl_pe_table_name = intermed.IntermediateSymbolTable.create(bl_context,
                                                                constructed.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)

        # Iterate through running processes from the baseline image
        for proc in constructed.list_processes(bl_context, layer_name = bl_kernel.layer_name, symbol_table = bl_kernel.symbol_table_name):
            if proc.ProcessExiting != 0: # Skip exited processes
                continue

            if not proc.Peb or proc.Peb == None: # Skip processes without PEB
                continue

            proc_layer_name = proc.add_process_layer()

            # Get PEB of current process
            peb = bl_context.object(bl_kernel.symbol_table_name + constants.BANG + "_PEB",
                                layer_name = proc_layer_name,
                                offset = proc.Peb)

            process_image_path = peb.ProcessParameters.ImagePathName.get_string().lower()

            # The list of baseline processes is maintained in the baseline process list dictionary 'baseline_proc_list'.
            # It is checked whether the process is already in this list
            if process_image_path not in self.baseline_proc_list:
                # Process is not found in the baseline process list and thus a new process object is generated.
                proc_obj_new = {
                    'pid'   : [],
                    'ppid'  : [],
                    'image' : proc.ImageFileName.cast('string',
                                                max_length = proc.ImageFileName.vol.count,
                                                errors = 'replace').lower() or '',
                    'path'  : peb.ProcessParameters.ImagePathName.get_string().lower() if peb.ProcessParameters != None else '',
                    'cmd'   : peb.ProcessParameters.CommandLine.get_string().lower() if peb.ProcessParameters != None else '',
                    'offset': [],
                    'exited': [],
                    'dlls' : {
                        'load': {}, # load list
                        'mem' : {}, # mem list
                        'init': {}, # init list
                        'comb': {}, # combined list, contains all dlls
                        'vad' : {}  # vad list
                    }
                }

                # Add the new process object to the baseline process list
                self.baseline_proc_list[proc_obj_new['path']] = proc_obj_new

            # Get process from baseline process list
            proc_obj = self.baseline_proc_list[process_image_path]

            # Enrich the process object with ProcessID, ParentProcessID and the offset.
            # The same image can be started multiple times, hence the information is stored in a list.
            proc_obj['pid'].append(int(proc.UniqueProcessId))
            proc_obj['ppid'].append(int(proc.InheritedFromUniqueProcessId))
            proc_obj['offset'].append(proc.vol.offset)

            # Enrich the process object with DLLs registered in the LoadOrder, InitializationOrder and MemoryOrder module list
            proc_obj = self.enrich_procobj_with_dll(proc, proc_obj, 'load')
            proc_obj = self.enrich_procobj_with_dll(proc, proc_obj, 'mem')
            proc_obj = self.enrich_procobj_with_dll(proc, proc_obj, 'init')


            proc_obj = self.add_missing_modules_vads(bl_context, proc, bl_pe_table_name, proc_layer_name, proc_obj)
        

        #########################################################
        # Search for the processes in the image to be analyzed. #
        #########################################################
        kernel = self.context.modules[self.config['kernel']]
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                constructed.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)


        for proc in pslist.PsList.list_processes(self.context, layer_name = kernel.layer_name, symbol_table = kernel.symbol_table_name):
            if proc.ProcessExiting != 0: # Skip exited processes
                continue

            if not proc.Peb or proc.Peb == None:
                continue

            proc_layer_name = proc.add_process_layer()

            # Get full image path
            peb = self.context.object(kernel.symbol_table_name + constants.BANG + "_PEB",
                                layer_name = proc_layer_name,
                                offset = proc.Peb)

            proc_obj = {
                'pid'   : int(proc.UniqueProcessId),
                'ppid'  : int(proc.InheritedFromUniqueProcessId),
                'image' : proc.ImageFileName.cast('string',
                                            max_length = proc.ImageFileName.vol.count,
                                            errors = 'replace').lower() or '',
                'path'  : peb.ProcessParameters.ImagePathName.get_string().lower() if peb.ProcessParameters != None else '',
                'cmd'   : peb.ProcessParameters.CommandLine.get_string().lower() if peb.ProcessParameters != None else '',
                'offset': proc.vol.offset,
                'exited': [],
                'dlls' : {
                    'load': {}, # load list
                    'mem' : {}, # mem list
                    'init': {}, # init list
                    'comb': {}, # combined list, contains all dlls
                    'vad' : {}  # vad list
                }
            }

            proc_obj = self.enrich_procobj_with_dll(proc, proc_obj, 'load')
            proc_obj = self.enrich_procobj_with_dll(proc, proc_obj, 'mem')
            proc_obj = self.enrich_procobj_with_dll(proc, proc_obj, 'init')

            proc_obj = self.add_missing_modules_vads(self.context, proc, pe_table_name, proc_layer_name, proc_obj)
            
            self.image_proc_list.append(proc_obj)


        ######################################
        # Compare processes from both lists. #
        ######################################
        for proc in self.image_proc_list: # Check all the processes in the image to be analyzed
            image = proc['path']
            # Set process found by default to 'False'
            p_found = False

            if image in self.baseline_proc_list: 
                proc_bl = self.baseline_proc_list[image]
                # If the process is found, i.e. the image path matched, set process found to 'True'
                p_found = True

                if self.config.get("verbose"):
                    for comb_mod in proc['dlls']['comb']:
                        # Check if DLL is in combined list of baseline image
                        m_found = False
                        for mod_bl in self.baseline_proc_list[image]['dlls']['comb']:
                            if proc['dlls']['comb'][comb_mod]['dll'] == proc_bl['dlls']['comb'][mod_bl]['dll']:
                                m_found = True
                        
                        # Check in which list it is in the baseline image, i.e. checking DLL from combined list against 'load', 'init' and 'mem' list
                        bl_mod_load_found = False
                        for mod_bl in self.baseline_proc_list[image]['dlls']['load']:
                            if proc['dlls']['comb'][comb_mod]['dll'] == proc_bl['dlls']['load'][mod_bl]['dll']:
                                bl_mod_load_found = True
                        
                        bl_mod_init_found= False
                        for mod_bl in self.baseline_proc_list[image]['dlls']['init']:
                            if proc['dlls']['comb'][comb_mod]['dll'] == proc_bl['dlls']['init'][mod_bl]['dll']:
                                bl_mod_init_found = True

                        bl_mod_mem_found= False
                        for mod_bl in self.baseline_proc_list[image]['dlls']['mem']:
                            if proc['dlls']['comb'][comb_mod]['dll'] == proc_bl['dlls']['mem'][mod_bl]['dll']:
                                bl_mod_mem_found = True

                        # Check in which list it is in analysing image, i.e. checking DLL from combined list against 'load', 'init' and 'mem' list
                        mod_load_found = False
                        if proc['dlls']['comb'][comb_mod]['dll'] in proc['dlls']['load']:
                            mod_load_found = True
                        
                        mod_init_found = False
                        if proc['dlls']['comb'][comb_mod]['dll'] in proc['dlls']['init']:
                            mod_init_found = True

                        mod_mem_found = False
                        if proc['dlls']['comb'][comb_mod]['dll'] in proc['dlls']['mem']:
                            mod_mem_found = True

                        # Output process if neither '--onlyknown' nor '--onlyunknown' is set
                        if not self.config.get("onlyknown") and not self.config.get("onlyunknown"):
                            yield(0, [format_hints.Hex(proc['offset']), proc['image'], proc['path'], proc['pid'], proc['ppid'], p_found, format_hints.Hex(proc['dlls']['comb'][comb_mod]['base']), format_hints.Hex(proc['dlls']['comb'][comb_mod]['size']), m_found, mod_load_found, mod_init_found, mod_mem_found, bl_mod_load_found, bl_mod_init_found, bl_mod_mem_found, proc['dlls']['comb'][comb_mod]['dll']])
                    
                        # If the '--onlyknown' is set, output the process if it also found in the baseline image
                        if self.config.get("onlyknown") and m_found:
                            yield(0, [format_hints.Hex(proc['offset']), proc['image'], proc['path'], proc['pid'], proc['ppid'], p_found, format_hints.Hex(proc['dlls']['comb'][comb_mod]['base']), format_hints.Hex(proc['dlls']['comb'][comb_mod]['size']), m_found, mod_load_found, mod_init_found, mod_mem_found, bl_mod_load_found, bl_mod_init_found, bl_mod_mem_found, proc['dlls']['comb'][comb_mod]['dll']])
                        
                        # If the '--onlyknown' is set, output the process if it also found in the baseline image
                        if self.config.get("onlyunknown") and not m_found:
                            yield(0, [format_hints.Hex(proc['offset']), proc['image'], proc['path'], proc['pid'], proc['ppid'], p_found, format_hints.Hex(proc['dlls']['comb'][comb_mod]['base']), format_hints.Hex(proc['dlls']['comb'][comb_mod]['size']), m_found, mod_load_found, mod_init_found, mod_mem_found, bl_mod_load_found, bl_mod_init_found, bl_mod_mem_found, proc['dlls']['comb'][comb_mod]['dll']])

                else:
                    # Output process if neither '--onlyknown' nor '--onlyunknown' is set
                    if not self.config.get("onlyknown") and not self.config.get("onlyunknown"):
                        yield(0, [format_hints.Hex(proc['offset']), proc['image'], proc['path'], proc['pid'], proc['ppid'], p_found])

                    # If the '--onlyknown' is set, output the process if it also found in the baseline image
                    if self.config.get("onlyknown") and p_found:
                        yield(0, [format_hints.Hex(proc['offset']), proc['image'], proc['path'], proc['pid'], proc['ppid'], p_found])

            else: 
                # The process is not found.
                if self.config.get("verbose"):
                    m_found = False
                    for comb_mod in proc['dlls']['comb']:
                        mod_load_found = False
                        if proc['dlls']['comb'][comb_mod]['dll'] in proc['dlls']['load']:
                            mod_load_found = True

                        mod_init_found = False
                        if proc['dlls']['comb'][comb_mod]['dll'] in proc['dlls']['init']:
                            mod_init_found = True

                        mod_mem_found = False
                        if proc['dlls']['comb'][comb_mod]['dll'] in proc['dlls']['mem']:
                            mod_mem_found = True

                        # If the '--onlyknown' flag is not set, output the process
                        if not self.config.get("onlyknown"):
                            yield(0, [format_hints.Hex(proc['offset']), proc['image'], proc['path'], proc['pid'], proc['ppid'], p_found, format_hints.Hex(proc['dlls']['comb'][comb_mod]['base']), format_hints.Hex(proc['dlls']['comb'][comb_mod]['size']), m_found, mod_load_found, mod_init_found, mod_mem_found, False, False, False, proc['dlls']['comb'][comb_mod]['dll']])
                else:
                    # If the '--onlyknown' flag is not set, output the process
                    if not self.config.get("onlyknown"):
                        yield(0, [format_hints.Hex(proc['offset']), proc['image'], proc['path'], proc['pid'], proc['ppid'], p_found])

    def run(self):
        if self.config.get("verbose"):
            return renderers.TreeGrid([("Process Offset", format_hints.Hex),
                            ("Image Name ", str),
                            ("Image Path", str),
                            ("PID", int),
                            ("PPID", int),
                            ("PFOUND", bool),
                            ("DLL_Base(I)(V)", format_hints.Hex),
                            ("DLL_Size(I)", format_hints.Hex),
                            ("MFOUND", bool),
                            ("L(I)", bool),
                            ("I(I)", bool),
                            ("M(I)", bool),
                            ("L(B)", bool),
                            ("I(B)", bool),
                            ("M(B)", bool),
                            ("DLL Image Name", str)],
                            self._generator())
        else:
            return renderers.TreeGrid([("Process Offset", format_hints.Hex),
                            ("Image Name ", str),
                            ("Image Path", str),
                            ("PID", int),
                            ("PPID", int),
                            ("PFOUND", bool)],
                            self._generator())
