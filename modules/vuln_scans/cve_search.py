import ares
from galvatron_lib.core.module import BaseModule
import json

class Module(BaseModule):
    meta = {
            "name": "CVE Search",
            "author": "Mike West",
            "descrription": "uses www.circl.lu to search for CVEs",
            "query": "SELECT DISTINCT product_name, vendor, version FROM targets WHERE location IS NOT NULL"
    }

    def module_run(self, params):
        api = ares.CVESearch()

        for p in params:
            product_name, vendor, version = p
            #cpe_string = "cpe:/a:%s:%s:%s::" % (vendor.lower(), product_name.lower(), version)
            #self.output("Searching for CPE: %s" % cpe_string)
            results = api.search("{}/{}".format(vendor, product_name))

            for result in results:
                cve_number = result["id"]
                published = result["Published"]
                description = result["summary"]
                cvss = result["cvss"]

                self.add_cve(product_name, version, cve_number, description, published, cvss)




