from galvatron_lib.core.module import BaseModule
import os
import fnmatch
import subprocess
import re

class Module(BaseModule):
    meta = {
        "name": "Hakiri",
        "author": "Mike West",
        "description": "Checks ruby Gemfile.lock for vunerable dependencies",
        "query": "SELECT DISTINCT product_name, version, extracted_location FROM targets WHERE extracted_location IS NOT NULL"
    }

    def module_pre(self):
        if os.system("which bundle-audit >/dev/null") != 0:
            self.alert("bundle-audit is not installed, installing")
            os.system("sudo gem install bundle-audit")


    def module_run(self, params):
        for product, version, extracted_location in params:

            directory = ""
            for root, dirnames, filenames in os.walk(extracted_location):
                for filename in fnmatch.filter(filenames, "Gemfile"):
                    if directory == "":
                        directory = root

            os.chdir(directory)
            gemfile = "%s/Gemfile" % directory
            self.output("Generating standalone bundle")
            os.system("bundle install --gemfile=%s --standalone" % gemfile)

            self.output("Scanning: %s.lock..." % gemfile)
            scanner = subprocess.Popen(["bundle-audit", "--update"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)

            output, error = scanner.communicate()
            details = re.split("ruby-advisory-db: \d+ advisories\n",output)[1].strip()

            if details == "No vulnerabilities found":
                self.output(details)
            else :
                results = re.split("\n\s*\n", details)
                for result in results:
                    if not result.startswith("Name"):
                        continue

                    t = result.split("\n")
                    cve = t[2].split(": ")[1].strip()
                    url = t[4].split(": ")[1].strip()
                    title = t[5].split(": ")[1].strip()
                    description = "%s - (%s)" % (title, url)

                    self.add_cve(product, version, cve, description, "N/A")

