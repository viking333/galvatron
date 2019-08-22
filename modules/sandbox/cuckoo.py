from galvatron_lib.core.module import BaseModule
import json
import os
import requests

class Module(BaseModule):
    meta = {
            "name": "Cuckoo Sandbox Submit",
            "author": "Mike West",
            "descrription": "Submits the target to the cuckoo sandbox",
            "query": "SELECT DISTINCT ROWID, location, product_name, version, sandbox_id FROM targets WHERE location IS NOT NULL",
            "options": [
                ["cuckoo_url", "http://192.168.27.3:8888", True, 'cuckoo api to submit to'],
                ["package", None, False, 'cuckoo analysis package to use'],
                ["platform", "windows", True, 'platform the analysis should run on'],
                ["options", None, False, 'options for the analysis'],
                ["mem_dump", False, True, 'whether to perform full memory analysis on the file'],
                ["view_web_report", False, True, 'if set to true will open your browser to the cuckoo web interface for this report'],
                ["cuckoo_web_url", "http://192.168.27.3:8777", True, 'url for the cuckoo web interface']
            ]
    }

    def module_run(self, params):
        self.submit_url = "%s/tasks/create/file" % self.options["cuckoo_url"]
        self.status_url = "%s/tasks/view" % self.options["cuckoo_url"]
        self.report_url = "%s/tasks/report" % self.options["cuckoo_url"]

        for t in params:
            self.rowid, self.location, self.product_name, self.version, self.sandbox_id = t

            if not self.sandbox_id:
                self.output("Submitting %s to sandbox" % self.location)
                self.submit_new_sample()
            else:
                self.output("Getting status for %s" % self.location)
                self.get_status()

    def submit_new_sample(self):
        with open(self.location, "rb") as s:
            self.output("Building request")

            req = {"file": (os.path.basename(self.location), s)}
            other = {"platform": self.options['platform']}

            if self.options['options']:
                other["options"] = self.options["options"]

            if self.options['package']:
                other["package"] = self.options["package"]

            if self.options['mem_dump']:
                other["memory"] = True

            self.output("Submitting request to %s" % self.submit_url)
            self.output("Request: %s" % other)
            response = requests.post(self.submit_url, files=req, data=other)

            self.output("Got response: %s" % response)
            json_decoder = json.JSONDecoder()
            task_id = json_decoder.decode(response.text)["task_id"]

            self.query("UPDATE targets SET sandbox_id = '%s' WHERE ROWID = %s" % (task_id, self.rowid))
            self.output("Submitted: %s to the sandbox and retrieved task id: %s" % (self.location, task_id))

    def get_status(self):
        url = "%s/%s" % (self.status_url, self.sandbox_id)

        self.output("Getting status from %s" % url)
        response = requests.get(url)

        json_decoder = json.JSONDecoder()
        status = json_decoder.decode(response.text)["task"]["status"]

        self.output("Status for task: %s is %s" % (self.sandbox_id, status))

        if status == "reported":
            self.process_report()

    def process_report(self):
        if self.options["view_web_report"]:
            url = "%s/analysis/%s" % (self.options["cuckoo_web_url"], self.sandbox_id)
            os.system("xdg-open %s" % url)
            return

        url = "%s/%s" % (self.report_url, self.sandbox_id)

        self.output("Getting report from %s" % url)
        response = requests.get(url)

        json_decoder = json.JSONDecoder()
        report = json_decoder.decode(response.text)
        sigs = report["signatures"]

        for s in sigs:
            self.add_sandbox_result(self.product_name, self.version, s["description"], s["severity"])

