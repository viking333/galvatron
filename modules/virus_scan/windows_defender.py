from galvatron_lib.core.module import BaseModule
from galvatron_lib.core.framework import FrameworkException, Colors
import os
import subprocess
import re 
from _winreg import *

class Module(BaseModule):
    meta = {
            "name": "Windows Defender AV Scanner",
            "author": "Mike West",
            "description": "This plugin windows defender anti-virus to scan for viruses",
            "query": "SELECT DISTINCT location, product_name, version FROM targets WHERE location IS NOT NULL",
            "options": [
              ["defender_exe","%ProgramFiles%\\Windows Defender\\mpcmdrun.exe", True, "The location of the windows defender cli tool"]
            ]
    }

    def module_pre(self):
      self.options["defender_exe"] = os.path.expandvars(self.options["defender_exe"])

      if os.path.isfile(self.options["defender_exe"]) == False:
        raise FrameworkException('Windows defender not found.')

      try:
        lm = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        defender = OpenKey(lm, r"SOFTWARE\Microsoft\Windows Defender\Signature Updates")
        self.engine_version = QueryValueEx(defender, "EngineVersion")[0]
        self.av_version = QueryValueEx(defender, "AVSignatureVersion")[0]
      except:
        raise FrameworkException("Could not get Windows Defender Version Info...")
      finally:
        CloseKey(defender)
        CloseKey(lm)

    def module_run(self, params):
      threat = re.compile("^Threat\s+: (.*)$")

      for i in params:
        location, product_name, version = i
        self.output("Scanning: %s" % location)

        output = ""
        try:
          output = subprocess.check_output([self.options["defender_exe"], "-Scan", "-ScanType", "3", "-File", "\"" + location + "\"", "-DisableRemediation"])
        except subprocess.CalledProcessError as ex:
          output = ex.output if ex.output else output

        for log_line in output.split("\n"):
          match = threat.match(log_line)
          if match:                      
            self.add_virus(product_name, version, "Windows Defender", self.engine_version, self.av_version, match.group(1).rstrip())
