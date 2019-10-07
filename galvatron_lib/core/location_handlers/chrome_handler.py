import os, urllib, requests, json
priority = 1

def get_extension_id(arg1):
    package = "\"{}\"".format(arg1.replace("chrome://", ""))
    package = urllib.quote_plus(package)

    url = "https://chrome.google.com/webstore/ajax/item?hl=en&gl=GB&pv=20181009&count=2&searchTerm={}".format(package)
    resp = requests.post(url)
    data = json.loads(resp.text.replace(")]}'\n\n", ""))
    items = [x[0] for x in data[1][1] if x[1] == arg1.replace("chrome://", "")]
    if len(items):
        return items[0]

    return None

def download_extension(app, extension_id, browser_version="49.0"):
    url = "https://clients2.google.com/service/update2/crx?response=redirect&acceptformat=crx3&prodversion={version}&x=id%3D{extension_id}%26installsource%3Dondemand%26uc".format(version=browser_version, extension_id=extension_id)
    dest_location = os.path.join(os.sep, "tmp", "{}.zip".format(extension_id))
    print(dest_location)
    try:
        urllib.urlretrieve(url, dest_location)
    except Exception as ex:
        app.output(ex)
        return None

    return dest_location

def handles(location):
    return location.lower().startswith("chrome://")

def handle(app, location):
    extension_id = get_extension_id(location)
    if extension_id:
        app.output("Downloading chrome extension {}".format(extension_id))
        return (download_extension(app, extension_id), None)
    else:
        app.error("Chrome extension not found")                
        return (None, None)
