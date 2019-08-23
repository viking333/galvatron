from galvatron_lib.core.regex_module import RegexModule


class Module(RegexModule):
	meta = {
		"name": "GoLang regex scanner",
		"author": "James Hancox",
		"description": "Uses regexes to search for potentially dangerous GoLang code",
		"query": "SELECT DISTINCT extracted_location, product_name, version FROM targets WHERE location IS NOT NULL"
	}


	def file_name_regex(self):
		return ".*\.go"


	def line_regex(self):
		return [
		    ("\"unsafe\"", "Use of unsafe function(s)"),
			("\"os/exec\"", "Potential for code execution"),
			("Cmd.", "Potential for code exection"),
			("net.", "Networking library usage"),
			("\"math/random\"", "Unsecure random function")
			]
