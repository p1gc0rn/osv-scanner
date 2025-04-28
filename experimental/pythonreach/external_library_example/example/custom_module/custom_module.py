import transitive_module.module
import requests

def using_transitive_module():
    return transitive_module.module.print_module_name("using_trasitive_module")

def fetch_data_from_lib(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error in custom_lib_folder: {e}")
        return None