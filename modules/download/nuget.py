from galvatron_lib.core.module import BaseModule
from galvatron_lib.core.framework import FrameworkException, Colors
import os
import requests
from datetime import datetime
import distutils.spawn
import re
import shutil


class Module(BaseModule):
    meta={
        "name" : "NuGet Packages Downloader",
        "author" : "Lukasz Malendowicz",
        "description" : "This plugin will download given nuget packages and scan them using Clam and Sophos AV. The user needs to provide a text file using 'target add' containing required packages (one package on each line). If specific version is required, it can be specified by appending it to the package in the following way 'PACKAGENAME/VERSION'",
        "query" : "SELECT DISTINCT location  FROM targets WHERE location IS NOT NULL"
    }

    def module_pre(self):
        self.zip_path = distutils.spawn.find_executable('zip')
        self.clam_path = distutils.spawn.find_executable('clamscan')
        self.sophos_path = distutils.spawn.find_executable('savscan')
        if not self.zip_path:
            raise FrameworkException('ZIP is not installed.')
        elif not self.clam_path:
            raise FrameworkException('Clam AV is not installed.')
        elif not self.sophos_path:
            raise FrameworkException('Sophos AV is not installed.')

    def module_run(self, params):
        for i in params:
            location = i

            #create folder for the below download
            today = datetime.now()
            self.folder_name = "/tmp/galvatron_download_" + today.strftime("%d_%m_%H-%M")
            os.mkdir(self.folder_name)

            #open provided file and collect packages to be downloaded
            with open(location) as f:
                packages_list = f.readlines()

                #download and save packages
                self.alert("%s***** Downloading packages *****%s" % (Colors.O, Colors.N))
                for p in packages_list:
                    package = p.strip()
                    downloadURL = "https://www.nuget.org/api/v2/package/" + package
                    r = requests.get(downloadURL, allow_redirects=True)

                    #allowing redirections and grabbing the file niem from the final address
                    final_url_parts = r.url.split('/')
                    filename= final_url_parts[-1]

                    with open(self.folder_name +'/'+filename, 'wb') as f:
                        f.write(r.content)

                    self.output("Downloaded %s package" % filename)

                # scan the packages
                self.alert("%s***** Scanning Downloaded packages *****%s" % (Colors.O, Colors.N))

                #clam-av scan
                os.system(self.clam_path + " " + self.folder_name + " >> /tmp/clam_av.log")
                clam_content = open("/tmp/clam_av.log").read()
                p = re.compile('.*(?P<package>\/\S+):\s(?P<virus_description>\S+)\sFOUND')

                for match in p.finditer(clam_content):
                    package_name = match.group('package')
                    description = match.group('virus_description') + " found in " + package_name
                    self.add_virus(package_name, "N/A", "Clam-AV", "", "", description)
                    self.output("Clam AV has detected %s" % description)

                #sophos-av scan
                os.system(self.sophos_path + " -f -all " + self.folder_name + " >>  /tmp/sophos_av.log")

                sophos_content = open("/tmp/sophos_av.log").read()
                p = re.compile(">>>\sVirus\s+'(?P<virus_description>\S+)'.*(?P<package>\/\S+)")

                for match in p.finditer(sophos_content):
                    package_name = match.group('package')
                    description = match.group('virus_description') + " found in " + package_name
                    self.add_virus(package_name, "N/A", "Sophos", "", "", description)
                    self.output("Sophos has detected %s" % description)

                self.output("AV scan is now completed")

                #Zip the files up and save to /tmp location
                self.alert("%s*****Ziping up the files *****%s" % (Colors.O, Colors.N))
                os.system("zip -q -r " + self.folder_name + " " + self.folder_name)

                self.output("Zip completed. The file can be found under " + self.folder_name + ".zip")

    def module_post(self):
        shutil.rmtree(self.folder_name)
        os.remove('/tmp/sophos_av.log')
        os.remove('/tmp/clam_av.log')
