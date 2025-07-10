import json
from io import StringIO


def parse_json_output(data: str):
    objs = []
    buf = ""
    for line in StringIO(data):
        buf += line
        try:
            obj = json.loads(buf)
            objs.append(obj)
            buf = ""
        except json.JSONDecodeError:
            continue  # wait until the full object is accumulated
    return objs
