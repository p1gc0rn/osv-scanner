import ast
import sys

def parse_functions_from_file(function_name, file_path):
    with open(file_path, 'r') as f:
        source_code = f.read()
    tree = ast.parse(source_code)
    imported_modules = {}
    used_functions = set()
    
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
    
    print(imported_modules)
    # Look into functions and see if the imports are called.
    for node in tree.body:
        if isinstance(node, ast.FunctionDef): 
            if function_name == node.name:
                for current_node in ast.walk(node): 
                    # Capture the explicitly called functions (module.function())
                    if isinstance(current_node, ast.Call):
                        if isinstance(current_node.func, ast.Attribute):
                            if isinstance(current_node.func.value, ast.Name):
                                if current_node.func.value.id in imported_modules:
                                    used_functions.add(f"{current_node.func.value.id}.{current_node.func.attr}")
                        else: 
                            for imported_module in imported_modules:
                                for imported_function in imported_modules[imported_module]:
                                    if current_node.func.id == imported_function:
                                        used_functions.add(current_node.func.id)
    return used_functions

if __name__ == "__main__":
    if len(sys.argv) > 2:
        function_name = sys.argv[1]
        paths = sys.argv[2].split(",")
        for path in paths: 
            function_data = parse_functions_from_file(function_name, path)
            if len(function_data) > 0:
                print(function_data)
            else:
                print("No transitive deps found")
    else:
        print("No args were provided")