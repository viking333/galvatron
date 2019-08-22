from galvatron_lib.core.regex_module import RegexModule

class Module(RegexModule):
    meta = {
            "name": "Java regex Scanner",
            "author": "Mike West",
            "descrription": "Uses regexes to search for potentially dangerous code",
            "query": "SELECT DISTINCT extracted_location, product_name, version FROM targets WHERE location IS NOT NULL"
    }

    def file_name_regex(self):
        return ".*\.java"

    def line_regex(self):
        return [("defineClass\(\S+\)|URLClassLoader\(\S+\)", "Code Execution"),
		("getBeanInfo\(\S+\)", "Code Execution"),
		("\.delete\(\S+\)", "Deleting Files"),
		("\.renameTo\(\S+\)", "Renaming Files"),
		("\.listFiles\(\S+\)|\.list\(\S+\)", "Directory Listing"),
		("FileInputStream\(\S+\)|FileOutputStream\(\S+\)|FileReader\(\S+\)|FileWriter\(\S+\)|RandomAccessFile\(\S+\)", "File Read/Write Access"),
		("Serializable\(\S+\)", "May lead to Remote code Execution. Case-Study: CVE-2013-2186 (Allows remote attackers to write to arbitrary files), CVE-2015-6576 (Deserialise arbitrary user input without restriction)"),
		("setProperty\(\S+\)|getProperties\(\S+\)|getProperty\(\S+\)", "Some system properties might contain information that is almost sensitive, and some system properties might alter the executon of critical stuff"),
		("loadLibrary\(\S+\)|load\(\S+\)", "Arbitrary Code Execution"),
		("keyPress\(\S+\)|keyRelease\(\S+\)|mouseMove\(\S+\)|mousePress\(\S+\)|mouseRelease\(\S+\)", "Maybe far-fetched since a server might not even have a graphical environment"),
		("getDeclaredMethod\(\S+\)|getDeclaredField\(\S+\)|reflection\.Method\.invoke\(\S+\)|reflection\.Field\.set\(\S+\)|reflection\.Field\.get\(\S+\)", "Depending on the circumstances it can lead from disclosure of sensitive information to code execution"),
		("ObjectStreamField\.getType\(\S+\)|ObjectStreamClass\.forClass\(\S+\)",""),
		("newInstance\(\S+\)|getClassLoader\(\S+\)|getClasses\(\S+\)|getField\(\S+\)|getFields\(\S+\)|getMethod\(\S+\)|getMethods\(\S+\)|getConstructor\(\S+\)|getConstructors\(\S+\)|getDeclaredClasses\(\S+\)|getDeclaredField\(\S+\)|getDeclaredFields\(\S+\)|getDeclaredMethod\(\S+\)|getDeclaredMethods\(\S+\)|getDeclaredConstructor\(\S+\)|getDeclaredConstructors\(\S+\)|getDeclaringClass\(\S+\)|getEnclosingMethod\(\S+\)|getEnclosingClass\(\S+\)|getEnclosingConstructor\(\S+\)|getParent\(\S+\)|getSystemClassLoader\(\S+\)|getContextClassLoader\(\S+\)","Certain standard APIs are potentially vulnerable when invoked by trusted code on behalf of untrusted code, or when operating on tainted inputs provided by untrusted code. The specific one can bypass SecurityManager checks under some circumstances, it can potentially be exploited by an attacker to gain access to sensitive data, to load malicious classes (and consequently execute arbitrary malicious code), or to perform sensitive operations."),
		("forName\(\S+\)|getConnection\(\S+\)","Arbitrary Code Execution. It can be exploited when (1) they are invoked indirectly by untrusted code and/or (2) they accept tainted inputs from untrusted code."),
		("asInterfaceInstance\(\S+\)|getInvocationHandler\(\S+\)|getProxyClass\(\S+\)|newProxyInstance\(\S+\)|getFields\(\S+\)|getSoundbank\(\S+\)|useCodebaseOnly\(\S+\)|trustURLCodebase\(\S+\)|setSecurityManager\(\S+\)|SecurityManager\(\S+\)", "Arbitrary Code Execution"),
		("exec\(\S+\)|ProcessBuilder\(\S+\)", "Generating native system input events"),
		("eval\(\S+\)", "Arbitrary Code Execution")]






