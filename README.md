This report will help the reader navigate a penetration test of Astley Jewellers' web application. The penetration test follows the OWASP Web Security Testing methodology, which has been altered by the tester to suit the client's requirements. Therefore, the tester has removed redundant sections and omitted sections that are not in scope.

When the tester began exploitation, they were able to gain access to the admin account and assign administrator privileges to other accounts. The tester also found multiple exploitable vulnerabilities, such as reflected XSS, stored XSS, SQLi, session fixation, session hijacking, sensitive credential exposure, and achieved root privileges on the server through local file inclusion. The existence of these vulnerabilities should provide enough tangible information for Astley Jewellers to recognise the necessity of improving their current security posture.


Summary of some identified weaknesses;

CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Directory Traversal

CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') Reflected XSS, Stored XSS

CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') SQL Injections

CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('Relative Path Traversal') Local File Inclusion

CWE-200 Information Exposure Information Leakage

CWE-269 Improper Privilege Management Privilege escalation

CWE-284 Improper Access Control Enabling admin access through user account

CWE-285 Improper Authorization Allocating admin rights with no secondary checks

CWE-287 Improper Authentication Lack of password policy & requirements

CWE-311 Missing Encryption of Sensitive Data No encryption used on transfer protocols

CWE-312 Cleartext Storage of Sensitive Information Exposure of sensitive information (credit cards) over post 
requests

CWE-319 Cleartext Transmission of Sensitive Information Cookies & authentication details sent in clear text

CWE-384 Session Fixation Session Fixation, Session Hijacking

CWE-613 Insufficient Session Expiration Predictable cookies

CWE-693 Protection Mechanism Failure Incorrect HTTP security headers:

CWE-798 Use of Hard-coded credentials default credentials

