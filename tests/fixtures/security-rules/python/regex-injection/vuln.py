# CWE-1333: user input compiled as a regex directly
import re
from flask import request


def search():
    re.compile(request.args.get("pattern", ""))
    return "ok"
