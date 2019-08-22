from galvatron_lib.core.regex_module import RegexModule
import json
import re
import os

class Module(RegexModule):
    meta = {
            "name": "Grep bugs regex Scanner",
            "author": "Mike West",
            "descrription": "Uses regexes from grepbugs.com to search for potentially dangerous code",
            "query": "SELECT DISTINCT extracted_location, product_name, version FROM targets WHERE extracted_location IS NOT NULL",
            "options": [
                ["force_refresh", False, True, 'force refreshing the rules list from grepbugs']
            ],
    }

    def module_pre(self):
        cache_file = os.path.join(self.data_path, "rules.json")

        if os.path.exists(cache_file) and not self.options['force_refresh']:
            self.output("Loading cached rules file")
            with open(cache_file) as f:
                rules = json.load(f)
        else:
            self.output("Getting regex from grepbugs...")
            rules = self.request("https://grepbugs.com/rules").json
            with open(cache_file, "w") as f:
                json.dump(rules, f)

        self.output("Compiling list of regexes by extension")
        self.regex_map = map(lambda x: (x['extension'].split(', '), re.compile(x['regex'], re.I), x['description']), rules)

    def get_ext_specific_regex(self, ext):
        ext = ext.lstrip('.')
        return [(x[1], x[2]) for x in self.regex_map if ext.lower() in x[0]]
