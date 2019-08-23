from galvatron_lib.core.regex_module import RegexModule


class Module(RegexModule):
	meta = {
	    "name": "erLang regex scanner",
	    "author": "James Hancox",
	    "description" : "Uses regexes to search for potentially dangerous ErLang code",
	    "query": "SELECT DISTINCT extracted_location, product_name, version FROM targets WHERE location IS NOT NULL"
	}


	def file_name_regex(self):
		return ".*\.erl"


	def line_regex(self):
		return [
            ("\"os:cmd\"", "potential for code execution"),
            ("\"secret_cookie\"", "unchanged default"),
            ("\"random\"", "possible unsafe usage of crypto functions"),
            ("\"open_port\"", "use of networking functions")
		]
