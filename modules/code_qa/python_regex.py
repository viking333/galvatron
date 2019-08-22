from galvatron_lib.core.regex_module import RegexModule

class Module(RegexModule):
    meta = {
            "name": "Python regex Scanner",
            "author": "Anastasios Koutlis",
            "description": "Uses regexes to search for potentially dangerous code in Python Files",
            "query": "SELECT DISTINCT extracted_location, product_name, version FROM targets WHERE location IS NOT NULL"
    }

    def file_name_regex(self):
        return ".*\.(py)"

    def line_regex(self):
        return [("^(?!(#|\*)).*(open\s?[\.|\(])","File Manipulation/Execute Arbitrary Code"),
		("^(?!(#|\*)).*(write\s?[\.|\(])","File Manipulation/Execute Arbitrary Code"),
		("^(?!(#|\*)).*(input\s?[\.|\(])","File Manipulation/Execute Arbitrary Code"),
		("^(?!(#|\*)).*(tarfile\s?[\.|\(])","File Manipulation"),
		("^(?!(#|\*)).*(zipfile\s?[\.|\(])","File Manipulation"),
		("^(?!(#|\*)).*(urllib2|socket\s?[\.|\(])","Network Calls"),
		("^(?!(#|\*)).*(pickle\s?[\.|\(])","Data Serialization/Persistence"),
		("^(?!(#|\*)).*(shelve\s?[\.|\(])","Data Serialization/Persistence"),
		("^(?!(#|\*)).*(subprocess|dircache\s?[\.|\(])","Process Thread Management, can cause command execution"),
		("^(?!(#|\*)).*(fork\s?[\.|\(])","Process Thread Management"),
		("^(?!(#|\*)).*(kill\s?[\.|\(])","Process Thread Management"),
		("^(?!(#|\*)).*(system\s?[\.|\(])","Can cause command execution"),
		("^(?!(#|\*)).*(spawn\s?[\.|\(])","Spawn New Processes"),
		("^(?!(#|\*)).*(popen\s?[\.|\(])","Can cause command execution"),
		("^(?!(#|\*)).*(commands\s?[\.|\(])","Command Execution"),
		("^(?!(#|\*)).*(getattr\s?[\.|\(])","Retrieve Attributes"),
		("^(?!(#|\*)).*(setattr\s?[\.|\(])","Add Attributes"),
		("^(?!(#|\*)).*(delattr\s?[\.|\(])","Delete Attributes"),
		("^(?!(#|\*)).*(execfile\s?[\.|\(])","File Execution"),
		("^(?!(#|\*)).*(file\s?[\.|\(])","File Execution"),
		("^(?!(#|\*)).*(eval\s?[\.|\(])","Arbitrary Code Execution"),
		("^(?!(#|\*)).*(exec\s?[\.|\(])","Code Execution"),
		("^(?!(#|\*)).*(__import__)","File Execution/Import")]


