# CWE-489: Flask debug mode enabled in production
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
