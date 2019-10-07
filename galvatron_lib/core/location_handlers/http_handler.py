import urllib
priority = 3

def handles(location):
    return location.lower().startswith("https://") or \
           location.lower().startswith("http://")

def handle(app, location):
    app.output("Downloading {}".format(location))
    
    try:
        tmp = urllib.urlretrieve(location)
        return (tmp[0], None)
    except Exception as ex:
        return (None, None)

