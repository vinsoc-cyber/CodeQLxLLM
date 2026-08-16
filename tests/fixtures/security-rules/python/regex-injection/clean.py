# re.escape — input treated as a literal substring, not a pattern
import re
from flask import request


def search():
    raw = request.args.get("pattern", "")
    pattern = re.compile(re.escape(raw))
    return "ok"
