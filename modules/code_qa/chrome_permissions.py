from galvatron_lib.core.module import BaseModule
import json
import os

class Module(BaseModule):
    meta = {
            "name": "Chrome Extension Permission",
            "author": "Mike West",
            "descrription": "Audits chrome extension permissions",
            "query": "SELECT DISTINCT extracted_location, product_name, vendor, version FROM targets WHERE location IS NOT NULL"
    }

    def parse_permissions(self, manifest):
        self.output(manifest['permissions'])
        pass

    def module_run(self, params):
        for p in params:
            location, product_name, vendor, version = p
            manifest = json.load(open(os.path.join(location, "manifest.json")))
            self.parse_permissions(manifest)

            


