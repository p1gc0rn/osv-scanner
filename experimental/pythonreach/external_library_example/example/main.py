from custom_module import custom_module

if __name__ == "__main__":
    data = custom_module.fetch_data_from_lib("https://jsonplaceholder.typicode.com/todos/1")
    if data:
        print("Data fetched by custom library:", data)