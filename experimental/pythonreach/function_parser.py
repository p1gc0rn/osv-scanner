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
            module_name = node.names[0].name  # Simplification for this example
            for alias in node.names:
                if module_name not in imported_modules:
                    imported_modules[module_name] = [alias.name]
                else:
                    imported_modules[module_name].append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module_name = node.module
            for alias in node.names:
                if module_name not in imported_modules:
                    imported_modules[module_name] = [alias.name]
                else:
                    imported_modules[module_name].append(alias.name)
    print(imported_modules)
    
    # Look into functions and see if the imports are called.
    for node in tree.body:
        if isinstance(node, ast.FunctionDef): 
            if function_name == node.name: 
                for node in ast.walk(node): 
                    if isinstance(node, ast.Name) and node.id in imported_modules:
                        pass
                    elif isinstance(node, ast.Attribute): 
                        if isinstance(node.value, ast.Name) and node.value.id in imported_modules:
                            used_functions.add(f"{node.value.id}.{node.attr}")
                    elif isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in imported_modules:
                            used_functions.add(f"{node.func.value.id}.{node.func.attr}")
    return used_functions

if __name__ == "__main__":
    if len(sys.argv) > 2:
        function_name = sys.argv[1]
        paths = sys.argv[2].split(",")
        for path in paths: 
            function_data = parse_functions_from_file(function_name, path)
            # try: 
            #     with open ('/usr/local/google/home/pnyl/osv-scanner/experimental/pythonreach/original/'+function_name, 'w') as file:
            #         file.write(function_data)
            #         print(f"Results successfully exported'")
            # except Exception as e:
            #     print(f"An error occurred: {e}")
    else:
        print("No paths were provided")
        