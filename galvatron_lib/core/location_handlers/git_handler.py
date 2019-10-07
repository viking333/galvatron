import os
priority = 2

def handles(location):
    return location.lower().startswith("http") and location.lower().endswith(".git")

def handle(app, location):
    extracted_location = "{}/repo".format(app.workspace)
    os.system("git clone {} {}".format(location, extracted_location))
    return (None, extracted_location)
