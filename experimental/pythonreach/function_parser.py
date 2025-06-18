import ast
import sys
import json

YELLOW = "\033[33m"
GREEN = "\033[32m"
RESET = "\033[0m"

def parse_functions_from_file(function_name, file_path):
    with open(file_path, 'r') as f:
        source_code = f.read()
    tree = ast.parse(source_code)
    imported_modules = {}
    used_modules_functions = {}
    
    # Find all top-level imports.
    for node in tree.body:
        if isinstance(node, ast.Import):
            module_name = node.names[0].name
            for alias in node.names:
                if alias.asname is not None: 
                    if alias.asname not in imported_modules:
                        imported_modules[alias.asname] = [alias.name]
                    else: 
                        imported_modules[alias.asname].append(alias.name)
                else: 
                    if module_name not in imported_modules:
                        imported_modules[module_name] = [alias.name]
                    else:
                        imported_modules[module_name].append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module_name = node.module
            for alias in node.names:
                if alias.asname is not None:    
                    if alias.asname not in imported_modules:
                        imported_modules[module_name] = [alias.asname]
                    else: 
                        imported_modules[module_name].append(alias.asname)
                else:
                    if module_name not in imported_modules:
                        imported_modules[module_name] = [alias.name]
                    else:
                        imported_modules[module_name].append(alias.name)
    
    #print(imported_modules)
    # Look into functions and see if the imports are called.
    for node in tree.body:
        if isinstance(node, ast.ClassDef): 
            for item in node.body: 
                if isinstance(item, ast.FunctionDef) and item.name == function_name: 
                    for current_node in ast.walk(item): 
                        # Capture the explicitly called functions (module.function())
                        if isinstance(current_node, ast.Call):
                            if isinstance(current_node.func, ast.Attribute):
                                if isinstance(current_node.func.value, ast.Name):
                                    if current_node.func.value.id in imported_modules:
                                        if used_modules_functions.get(current_node.func.value.id) is None:
                                            used_modules_functions[current_node.func.value.id] = [f"{current_node.func.value.id}.{current_node.func.attr}"]
                                        else:
                                            used_modules_functions[current_node.func.value.id].append(f"{current_node.func.value.id}.{current_node.func.attr}")
                                        #used_functions.add(f"{current_node.func.value.id}.{current_node.func.attr}")
                                    else:
                                        for imported_module in imported_modules:
                                            for imported_function in imported_modules[imported_module]:
                                                if current_node.func.value.id== imported_function:
                                                    if used_modules_functions.get(imported_module) is None:
                                                        used_modules_functions[imported_module] = [current_node.func.value.id]
                                                    else:
                                                        used_modules_functions[imported_module].append(current_node.func.value.id)
                                                    #used_functions.add(current_node.func.value.id)
                            else: 
                                for imported_module in imported_modules:
                                    for imported_function in imported_modules[imported_module]:
                                        if current_node.func.id == imported_function:
                                            if used_modules_functions.get(imported_module) is None:
                                                used_modules_functions[imported_module] = [current_node.func.id]
                                            else:
                                                used_modules_functions[imported_module].append(current_node.func.id)
                                            
    return used_modules_functions

if __name__ == "__main__":

    if len(sys.argv) > 2:
        function_name = sys.argv[1]
        paths = sys.argv[2].split(",")
        found = False
        for path in paths: 
            function_data = parse_functions_from_file(function_name, path)
            if len(function_data) > 0:
                new_function_data = {}
                # Traverese the dictionary 
                for key in function_data.keys():
                    new_function_data["imported_library"] = key
                    new_function_data["used_module"] = function_data[key]
                    print("Found:"+json.dumps(new_function_data))
                found = True
                break
        if found != True:
            print(f"{YELLOW}Not Found: No transitive deps found.{RESET}")
    else:
        print("No args were provided")
        