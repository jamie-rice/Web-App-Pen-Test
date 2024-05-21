# Web_App_Pen_Test
Using the OWAP Web Application Security Testing Methodology to provide a comprehensive Penetration Test Report of a fictious jewellery shop ‘Rick Astley Jewellers’

Some of the tools used  include:
•	Applications: Burp Suite, OWASP Zap
•	Scanning: Nikto, NMAP Wireshark
•	Investigating Cookie: Quick Cookie Manager, Web Scarab
•	Exploitation: SQLi Map, Browser Exploitation Framework (Beef)


Some of the vulnerabilities found and exploited on the web app are the following; 


CWE-22 	Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Directory Traversal

CWE-79 	Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')	Reflected XSS, Stored XSS

CWE-89 	Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')	SQL Injections

CWE-98 	Improper Control of Filename for Include/Require Statement in PHP Program ('Relative Path Traversal')	Local File Inclusion

CWE-200 	Information Exposure	Information Leakage

CWE-269 	Improper Privilege Management	Privilege escalation

CWE-284 	Improper Access Control	Enabling admin access through user account

CWE-285 	Improper Authorization	Allocating admin rights with no secondary checks

CWE-287 	Improper Authentication	Lack of password policy & requirements

CWE-311 	Missing Encryption of Sensitive Data	No encryption used on transfer protocols

CWE-312	Cleartext Storage of Sensitive Information	Exposure of sensitive information (credit cards) over post requests

CWE-319 	Cleartext Transmission of Sensitive Information	Cookies & authentication details sent in clear text

CWE-384 	Session Fixation	Session Fixation, Session Hijacking

CWE-613 	Insufficient Session Expiration	Predictable cookies

CWE-693 	Protection Mechanism Failure	Incorrect HTTP security headers:

CWE-798 	Use of Hard-coded credentials	Default credentials

These vulnerabilities and the processes used to find them are documented within the document
