# encoding: utf-8
from galvatron_lib.core.module import BaseModule
import json
import traceback
import os

class Module(BaseModule):
    meta = {
            "name": "Chrome Extension Permission",
            "author": "Mike West",
            "descrription": "Audits chrome extension permissions",
            "query": "SELECT DISTINCT extracted_location, product_name, vendor, version FROM targets WHERE location IS NOT NULL",
            "options": [
                ["bad_permissions", "network.config,power,proxy,system.cpu,system.display,system.memory,system.storage,unlimitedStorage,vpnProvider,browsingData,certificateProvider,dns,desktopCapture,enterprise.platformKeys,gcm,experimental,management,nativeMessaging,processes,filesystem,containsexe", True, "Permissions classed as risky"]
            ]
    }

    def module_pre(self):
        self.bad_permissions = set(self.options["bad_permissions"].split(","))

    def parse_permissions(self, manifest, product_name, version):
        
        bad_permissions = list()
        bad_permissions.append(dict(permission="wildcard", description="Access to data from all sites", enabled=0))
        bad_permissions.append(dict(permission="socket.tcp-listen", description="Runs a TCP socket server", enabled=0))
        bad_permissions.append(dict(permission="socket.tcp-connect", description="Connects to TCP server",enabled=0))
        bad_permissions.append(dict(permission="proxy", description="Modify proxy settings", enabled=0))
        bad_permissions.append(dict(permission="containsexe", description="Contains an executable - at a minimum this should be scanned with anti virus", enabled=0))
        bad_permissions.append(dict(permission="processes", description="Executes commands on the local system", enabled=0))
        bad_permissions.append(dict(permission="filesystem.write", description="Write to file system", enabled=0))
        bad_permissions.append(dict(permission="vpnProvider", description="VPN functionality", enabled=0))
        bad_permissions.append(dict(permission="nativeMessaging", description="Send messages to native applications", enabled=0))
        bad_permissions.append(dict(permission="desktopCapture", description="Screenshot capture", enabled=0))
        
        used_permissions = list()

        if "permissions" in manifest:
            for permission in manifest["permissions"]:
                if isinstance(permission, dict):
                    for key,value in permission.items():
                        if isinstance(value, list):
                            for item in value:
                                used_permissions.append(item)
                else:
                    used_permissions.append(permission)

        for permission in used_permissions:
            if permission == "tcp-listen":
                bad_permissions[1]["enabled"]=1
            if permission == "tcp-connect":
                bad_permissions[2]["enabled"]=1
            if permission == "proxy":
                bad_permissions[3]["enabled"]=1
            if permission == "containsexe":
                bad_permissions[4]["enabled"]=1
            if permission == "processes":
                bad_permissions[5]["enabled"]=1
            if permission == "write":
                bad_permissions[6]["enabled"]=1
            if permission == "vpnProvider":
                bad_permissions[7]["enabled"]=1
            if permission == "nativeMessaging":
                bad_permissions[8]["enabled"]=1
            if permission == "desktopCapture":
                bad_permissions[9]["enabled"]=1
            if permission == "<all_urls>" or permission == "*://*/*" or permission == "https://*/*" or permission == "http://*/*":
                bad_permissions[0]["enabled"]=1
               
            for permission in bad_permissions:
                if permission["enabled"]==1:
                    self.add_qa_issue(product_name, version, product_name, product_name, 0, permission["description"],permission["permission"])
        pass

    def module_run(self, params):
        for p in params:
            location, product_name, vendor, version = p
            try:
                manifest = json.load(open(os.path.join(location, "manifest.json")))
            except Exception as ex:
                self.output("!!! LOAD JSON !!!")
                self.output(location)
                self.output(ex)

            try:
                self.parse_permissions(manifest, product_name, version)
            except Exception as ex:
                self.output("!!! PARSE !!!")
                self.output(ex)
