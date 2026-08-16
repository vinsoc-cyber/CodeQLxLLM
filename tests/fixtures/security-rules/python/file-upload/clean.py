import os
from flask import request
from werkzeug.utils import secure_filename

def upload():
    f = request.files["file"]
    f.save(os.path.join("/uploads", secure_filename(f.filename)))
