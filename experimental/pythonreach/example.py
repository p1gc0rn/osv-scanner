# app.py
from flask import Flask, escape, request

app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name', 'World')
    return f'Hello, {escape(name)}!'

@app.route('/about')
def about():
    return 'This is a simple Flask application example.'

if __name__ == '__main__':
    app.run(debug=True)