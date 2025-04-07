from flask import Flask, make_response

app = Flask(__name__)

@app.route('/')
def index():
    response = make_response('Hello, World!')
    return response

if __name__ == '__main__':
    app.run(debug=True)
