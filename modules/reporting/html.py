from galvatron_lib.core.module import BaseModule
import os
import shutil
from mako.template import Template
from mako.lookup import TemplateLookup
import codecs
import base64

class Module(BaseModule):
    meta = {
            "name": "HTML Reporter",
            "author": "Mike West",
            "descrription": "Exports collected data to a html report",
            "query": "SELECT DISTINCT product_name, version FROM targets WHERE location IS NOT NULL",
            "options": [
                ["output_folder", os.path.join("/", "tmp", "galvatron-export"), True, 'path to export the report to']
            ],
    }

    def module_run(self, params):
        self.out_dir = self.options['output_folder']
        self.output("Generating output dir")
        self.plugin_dir = os.path.join(self.data_path, "report")
        self.template_dir = os.path.join(self.plugin_dir, "templates")
        self.styles_dir = os.path.join(self.plugin_dir, "styles")
        self.images_dir = os.path.join(self.plugin_dir, "images")
        os.makedirs(self.out_dir)

        self.output("Copying static assets...")
        shutil.copytree(self.styles_dir, self.out_dir + "/styles")
        shutil.copytree(self.images_dir, self.out_dir + "/images")

        for i in params:
            product, version = i

            report = {"title": "%s - %s - %s" % (product, version, os.path.basename(self.workspace))}

            # Gether virus scan data
            self.output("Gathering virus scan data....")
            tmp = self.query("SELECT engine, engine_version, update_version, description from virus_scan WHERE product = '%s'" % product)
            virus_scans = map(lambda x: {"engine": x[0],
                                         "version": x[1],
                                         "update": x[2],
                                         "virus": x[3]}, tmp)
            report["virus_scan"] = virus_scans

            self.output("Gathering cve data...")
            tmp = self.query("SELECT cve_number, published, description, cvss from cve WHERE product = '%s'" % product)
            cve = map(lambda x: {"cve_number": x[0],
                                 "published": x[1],
                                 "description": x[2],
                                 "cvss": x[3]}, tmp)
            report["cve"] = cve

            self.output("Gathering qa data...")
            tmp = self.query("SELECT file_name, location, line_number, description, note FROM qa_issue where product = '%s'" % product)
            qa_issue = map(lambda x: {"location": "%s/%s" % (x[1], x[0]),
                                      "line_number": "%s" % x[2],
                                      "code": self.to_unicode(x[3]),
                                      "note": x[4]}, tmp)

            report["qa_issue"] = qa_issue

            self.output("Gathering sandbox results data...")
            tmp = self.query("SELECT description, severity FROM sandbox_result where product = '%s'" % product)
            sandbox_result = map(lambda x: {"description": "%s" % x[0],
                                            "severity": "%s" % x[1]}, tmp)

            report["sandbox_result"] = sandbox_result

            self.output("Gathering captured http data...")
            tmp = self.query("SELECT method, url, data FROM url where product = '%s'" % product)
            http_data = map(lambda x: {"method": "%s" % x[0],
                                       "url": "%s" % x[1],
                                       "data": "%s" % x[2]}, tmp)

            for i in http_data:
                if i["data"] != "None":
                    i["data"] = base64.b64decode(i["data"])

            report["http_data"] = http_data
            self.process_report(report)

    def process_report(self, r):
        lookup = TemplateLookup(directories=[self.template_dir])
        template = lookup.get_template("report.html")

        self.output("Rendering template")
        output = template.render(report=r).encode("utf-8")
        output_filename = os.path.join(self.out_dir, r["title"], "%s.html" % r["title"])

        self.output("Writing file to %s" % os.path.dirname(output_filename))
        os.makedirs(os.path.dirname(output_filename))
        with open(output_filename, "w") as f:
            f.write(output)
