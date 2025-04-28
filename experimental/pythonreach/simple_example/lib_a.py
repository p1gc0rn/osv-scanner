#lib_a.py directly depends on lib_b.py

import lib_b
from lib_c import helper_function_lib_c
import lib_alias_import as lai
from another_lib_alias_import import helper_function as another_helper_function

def using_import_lib_c():
    data = helper_function_lib_c()
    print(f"[lib_a] lib_c helper_function_lib_c is called")

def using_import_lib_b():
    data = lib_b.helper_function()
    print(f"[lib_a] lib_b helper_function is called")
    return data

def using_lib_alias_import():
    data = lai.helper_function()
    print(f"[lib_a] lib_alias_import helper_function is called")
    return data

def using_another_lib_alias_import():
    data = another_helper_function()
    print(f"[lib_a] another_lib_alias_import helper_function is called")
    return data

def not_using_import():
    print(f"[lib_a] not_using_import is called")
    return "Lib A not_using_import"
