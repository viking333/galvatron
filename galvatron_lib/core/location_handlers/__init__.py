import os, glob, importlib

_path = os.path.dirname(os.path.abspath(__file__))
handlers = []

for h in  [".{}".format(os.path.basename(x).replace(".py", "")) for x in glob.glob("{}/*.py".format(_path)) if "__init__" not in x]:
    handlers.append(importlib.import_module(h, "galvatron_lib.core.location_handlers"))

handlers = sorted(handlers, key=lambda m: m.priority)

def get_handler(location):
    handler = [x for x in handlers if x.handles(location)][0]
    return handler
