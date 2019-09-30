from galvatron_lib.core.module import BaseModule
from galvatron_lib.core.framework import FrameworkException, Colors
import os
import subprocess
import re
import distutils.spawn

class Module(BaseModule):
    meta={
            "name" : "Clam Anti-Virus Scanner",
            "author" : "Lukasz Malendowicz",
            "description" : "This plugin uses Clam AV to scan given target files for viruses",
            "query" : "SELECT DISTINCT location, product_name, version FROM targets WHERE location IS NOT NULL"
            }

    def module_pre(self):
        self.clam_path = distutils.spawn.find_executable('clamscan')
        if not self.clam_path:
            raise FrameworkException('Clam is not installed. ')

    def module_run(self, params):
        engine_name = "ClamAV"
        for i in params:
            location, product_name, version = i
            self.output("Scanning: %s" % location)

            os.system(self.clam_path + " " + location + " -l clamav.log 2>&1 >/dev/null")
            content = open("clamav.log").read()
            p = re.compile('(?P<file>\S+):\s(?P<virus_description>\S+)\sFOUND')

        for match in p.finditer(content):
                description = match.group('virus_description') + " found in " + match.group('file')
                self.add_virus(product_name, version,  description)
                self.output("%s has detected %s" % (engine_name, description))

    def module_post(self):
        os.remove("clamav.log")


