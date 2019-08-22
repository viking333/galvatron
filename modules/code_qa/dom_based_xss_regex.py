from galvatron_lib.core.regex_module import RegexModule
import os
import re

class Module(RegexModule):
    meta = {
        "name": "DOM Based XSS regex Scanner",
        "author": "Anastasios Koutlis",
        "description": "Uses regexes to search for DOM based XSS",
        "query": "SELECT DISTINCT extracted_location, product_name, version FROM targets WHERE location IS NOT NULL"
    }

    def module_pre(self):
        self.sources = [("(location\s*[\[.])","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(arguments)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(dialogArguments)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(innerHTML)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(write(ln)?)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(open(Dialog)?)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(showModalDialog)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(cookie)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(URL)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(documentURI)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(baseURI)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(referrer)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(name)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(opener)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(parent)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(top)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(content)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(self)\W","DOM based XSS in Source"),
		("[.\[]\s*[\"\']?\s*(frames)\W","DOM based XSS in Source"),
		("localStorage","DOM based XSS in Source"),
		("sessionStorage","DOM based XSS in Source"),
		("Database","DOM based XSS in Source")]
       
        self.sinks = [("((src)\s*[\"\'\]]*\s*\+?\s*=)","DOM based XSS in Sink"),
		("((href)\s*[\"\'\]]*\s*\+?\s*=)","DOM based XSS in Sink"),
		("((data)\s*[\"\'\]]*\s*\+?\s*=)","DOM based XSS in Sink"),
		("((location)\s*[\"\'\]]*\s*\+?\s*=)","DOM based XSS in Sink"),
		("((code)\s*[\"\'\]]*\s*\+?\s*=)","DOM based XSS in Sink"),
		("((value)\s*[\"\'\]]*\s*\+?\s*=)","DOM based XSS in Sink"),
		("((action)\s*[\"\'\]]*\s*\+?\s*=)","DOM based XSS in Sink"),
		("((replace)\s*[\"\'\]]*\s*\()","DOM based XSS in Sink"),
		("((assign)\s*[\"\'\]]*\s*\()","DOM based XSS in Sink"),
		("((navigate)\s*[\"\'\]]*\s*\()","DOM based XSS in Sink"),
		("((getResponseHeader)\s*[\"\'\]]*\s*\()","DOM based XSS in Sink"),
		("((open(Dialog)?)\s*[\"\'\]]*\s*\()","DOM based XSS in Sink"),
		("((showModalDialog)\s*[\"\'\]]*\s*\()","DOM based XSS in Sink"),
		("((eval)\s*[\"\'\]]*\s*\()","DOM based XSS in Sink"),
		("((evaluate)\s*[\"\'\]]*\s*\()","DOM based XSS in Sink"),
		("((execCommand)\s*[\"\'\]]*\s*\()","DOM based XSS in Sink"),
		("((execScript)\s*[\"\'\]]*\s*\()","DOM based XSS in Sink"),
		("((setTimeout)\s*[\"\'\]]*\s*\()","DOM based XSS in Sink"),
		("((setInterval)\s*[\"\'\]]*\s*\()","DOM based XSS in Sink"),
		("after\(","DOM based XSS in Sink based on jQuery"),
		("\.before\(","DOM based XSS in Sink based on jQuery"),
		("\.html\(","DOM based XSS in Sink based on jQuery"),
		("\.prepend\(","DOM based XSS in Sink based on jQuery"),
		("\.replaceWith\(","DOM based XSS in Sink based on jQuery"),
		("\.wrap\(","DOM based XSS in Sink based on jQuery"),
		("\.wrapAll\(","DOM based XSS in Sink based on jQuery"),
		("\$\(","DOM based XSS in Sink based on jQuery"),
		("\.globalEval\(","DOM based XSS in Sink based on jQuery"),
		("\.add\(","DOM based XSS in Sink based on jQuery"),
		("jQUery\(","DOM based XSS in Sink based on jQuery"),
		("\.parseHTML\(","DOM based XSS in Sink based on jQuery")]
        
        self.output("Compiling source regexes")
        self.compiled_sources = [(re.compile(r[0]), r[1]) for r in self.sources]
        
        self.output("Compiling sink regexes")
        self.compiled_sinks = [(re.compile(r[0]), r[1]) for r in self.sinks]               
        
    def module_run(self, params):
        for target in params:
            location, product, version = target
            self.output("Scanning folder: %s" % location)
            for f in os.walk(location):
                dirpath, dirnames, filenames = f
                for x in filenames:
                    if re.match(self.file_name_regex(), x):
                        full_location = os.path.join(dirpath, x)
                        relative_location = full_location.replace(location + "/", "")
                        _, ext = os.path.splitext(full_location)
                        extra_regex = self.get_ext_specific_regex(ext)
                        self.scan_file(relative_location, full_location, product, version)

    def scan_file(self, relative_location, full_location, product_name, version):
        found_sources = {}
        found_sinks = {}
        with open(full_location) as f:
            for line_no, line in enumerate(f):
                line = line.rstrip()
                for r in self.compiled_sources:
                    m = r[0].search(line)
                    if m:
                        found_sources[line_no] = m
                        continue
                        
                for r in self.compiled_sinks:
                    m = r[0].search(line)
                    if m:
                        found_sinks[line_no] = m
                        continue
  
        for s in sorted(found_sources.keys()):
            if found_sinks.has_key(s):
                source_match = found_sources[s].group(0).strip().strip('.')
                sink_match = found_sinks[s].group(0).strip().strip('.')
                
                if source_match != sink_match:
                    self.add_qa_issue(product_name, version, os.path.basename(relative_location), os.path.dirname(relative_location), s + 1, found_sources[s].string,"High Probability DOM based XSS")
            else:                
                applicable = "\n".join(["%s: %s" % (k + 1, v.string) for k, v in found_sinks.iteritems() if abs(s - k) <= 50])
                if len(applicable) > 0:
                    self.add_qa_issue(product_name, version, os.path.basename(relative_location), os.path.dirname(relative_location), s + 1, found_sources[s].string, "Potential DOM based XSS:\n%s" % applicable)                            
        
            
    def file_name_regex(self):
        return ".*\.(js|html|aspx|cs|cshtml|ts)$"



