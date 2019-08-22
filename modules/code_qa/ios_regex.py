from galvatron_lib.core.regex_module import RegexModule

class Module(RegexModule):
    meta = {
            "name": "Swift/Objective C regex Scanner",
            "author": "Anastasios Koutlis",
            "descrription": "Uses regexes to search for potentially dangerous code",
            "query": "SELECT DISTINCT extracted_location, product_name, version FROM targets WHERE location IS NOT NULL"
    }

    def file_name_regex(self):
        return ".*\.(swift|m|h)"

    def line_regex(self):
        return [("^(?!(\*|\/)).*((NSLog|CFStringCreateWithFormat|CFStringCreateWithFormatAndArguments|CFStringAppendFormat|AEBuildDesc|AEBuildParameters|AEBuildAppleEvent)\()|(NSString\sstringWithFormat\:(?!@)|NSString\sinitWithFormat\:|NSMutableString\sappendFormat\:|NSAlert|NSPredicate\spredicateWithFormat\:|NSException\sraise\:|NSException\.raise\(|NSRunAlertPanel)", "Format String"),
		("^(?!(\*|\/)).*(strcat|strcpy|strncat|strncpy|(?![a-zA-Z])gets(?![a-zA-Z])|memcpy|fgets|vscanf|sscanf|vsscanf|vscanf|scanf|streadd|strecpy|strtrns|fscanf|vfscanf|realpath|syslog|getopt|getopt_long|getpass|getchar|fgetc|getc(?![a-zA-Z])|read(?![a-zA-Z])|bcopy|strccpy|strcadd|[a-z]{0,3}printf)", "Buffer Overflow"),
		("^(?!(\*|\/)).*(malloc\(|realloc\(|free\(|calloc\()", "Heap Overflow"),
		("^(?!(\*|\/)).*(Allowanyhttpscertificateforhost|continueWithoutCredentialForAuthenticationChallenge)", "Unvalidated ssl certs"),
		("^(?!(\*|\/)).*(system\(|popen\(|fork\(|WinExec\(|exec[a-z]{0,2}\()", "Command Injection")]






