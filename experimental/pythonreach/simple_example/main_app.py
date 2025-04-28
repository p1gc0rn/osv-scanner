import lib_a

if __name__ == "__main__":
    # data = lib_a.using_import()
    # print(f"[Main App] import lib_a and func using_import() is called")
    # data = lib_a.not_using_import()
    # print(f"[Main App] import lib_a and func not_using_import() is called")
    data = lib_a.using_another_lib_alias_import()
    print(f"[Main App] import lib_a and func lib_alias_import() is called")