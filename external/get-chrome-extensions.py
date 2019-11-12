#!/usr/bin/python3
import requests, json, sys, urllib
from os import path

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print ("[usage] python3 get-chrome-extensions.py <list-of-extensions.txt>")
        exit()

    list_of_extensions = sys.argv[1]
    if path.exists(list_of_extensions):
        try:
            os.remove("removed.txt")
            os.remove("chrome-extensions.rc")
        except:
            pass
        removed_list = open("removed.txt","a")
        rc_script = open("chrome-extensions.rc","a")
        package_fd = open(sys.argv[1])
        package_name = ""
        for package in package_fd.readlines():
            package = package.strip()
            package_name = package
            package = f"\"{package}\""
            package = urllib.parse.quote_plus(package)

            url = f"https://chrome.google.com/webstore/ajax/item?hl=en&gl=GB&pv=20181009&count=2&searchTerm={package}"
            resp = requests.post(url)
            data = json.loads(resp.text.replace(")]}'\n\n", ""))
            items = [x[0] for x in data[1][1] if x[1] == package_name]
            if len(items):
                rc_script.write("add targets chrome://"+package_name+"~"+package_name+"~"+package_name+"~~~~\n")
            else:
                removed_list.write(package_name+"\n")
    else:
        print("[!] ERROR: File containing extensions does not exist")
        exit()
