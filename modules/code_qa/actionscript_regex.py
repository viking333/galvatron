from galvatron_lib.core.regex_module import RegexModule

class Module(RegexModule):
    meta = {
            "name": "Actionscript regex Scanner",
            "author": "Bogdan Tiron - Anastasios Koutlis",
            "description": "Uses regexes to search for potentially dangerous code",
            "query": "SELECT DISTINCT extracted_location, product_name, version FROM targets WHERE location IS NOT NULL"
    }

    def file_name_regex(self):
        return ".*\.(as|fla|xml|swf)"

    def line_regex(self):
        return [("_root|_level0|_global","Global Variables, if they have an attribute that is undefined or not sanitized/validated it can lead to XSS etc."),
		("\.ExternalInterface.call\s*\(","The specific function can accept a JavaScript function name as the first argument and a string which would be sent to that JavaScript function. Accepting user input without having an input validation mechanism can cause XSS"),
		("\.(clickTAG|clickTag|ClickTAG|ClickTag)","Allowing unfiltered user input can lead into injecting javascript code or redirecting users to other websites"),
		("getURL\s*\(","Prone to XSS - Open Redirect, might cause the browser to execute JavaScript code, which may accomplish a Reflected XSS attack on the domain where the Flash application is hosted."),
		("navigateToURL\s*\(","Prone to XSS - Open Redirect, might cause the browser to execute JavaScript code, which may accomplish a Reflected XSS attack on the domain where the Flash application is hosted."),	
		("loadMovie\s*\(","Unsafe Method - Potential Injection Points"),
		("loadMovieNum\s*\(","Unsafe Method - Potential Injection Points"),
		("asfunction\:","Unsafe Method - Potential Injection Points"),
		("\.load","Unsafe Method - If the data is not filtered/validated using the right regexp it could lead to some security issue"),
		("loadVariables\s*\(","Unsafe Method - If the data is not filtered/validated using the right regexp it could lead to some security issue"),
		("LoadVars.load\s*\(*","Unsafe Method - If the data is not filtered/validated using the right regexp it could lead to some security issue"),
		("LoadVars.send","Unsafe Method - If the data is not filtered/validated using the right regexp it could lead to some security issue"),
		("FScrollPane.loadScrollContent\s*\(","Unsafe Method - If the data is not filtered/validated using the right regexp it could lead to some security issue"),
		("XML.load\s*\(","Unsafe Method - If the data is not filtered/validated using the right regexp it could lead to some security issue"),
		("Sound.loadSound\s*\(","Unsafe Method - If the data is not filtered/validated using the right regexp it could lead to some security issue"),
		("NetStream.play\s*\(","Unsafe Method - If the data is not filtered/validated using the right regexp it could lead to some security issue"),
		("\.htmlText","Unsafe Method - If the data is not filtered/validated using the right regexp it could lead to some security issue"),
		("eval\s*\(","Arbitrary Code Execution"),
		("NetStream.play","Unsafe Method - If the data is not filtered/validated using the right regexp it could lead to some security issue")]


