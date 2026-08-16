import os
from flask import request

def upload():
    f = request.files["file"]
    f.save(os.path.join("/uploads", f.filename))
