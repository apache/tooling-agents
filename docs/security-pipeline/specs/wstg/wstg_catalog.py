"""
WSTG catalog — every test in OWASP Web Security Testing Guide (latest).

Source: https://github.com/OWASP/www-project-web-security-testing-guide/tree/master/latest
Mirrored by:  https://owasp.org/www-project-web-security-testing-guide/latest/

Each entry has been classified along three axes that the multi-spec audit
pipeline cares about:

  category            — domain bucket for the consolidator (matches the WSTG
                        section name, lowercased)
  static_applicable   — True if this test can be meaningfully run as static
                        code review against a code namespace; False if it
                        fundamentally requires a deployed target
  level               — 1/2/3 mapping the architecture's L1/L2/L3 filter.
                          1 = baseline, expected for any web app
                          2 = standard, expected for apps handling sensitive data
                          3 = advanced, niche or specialist scenarios

WSTG IDs follow the deterministic pattern derived from section numbers:
  section "4.X.Y" → "WSTG-{PREFIX}-{Y:02d}"
  section "4.X.Y.Z" (sub-test) → "WSTG-{PREFIX}-{Y:02d}.{Z}"

Structure: list of dicts. Run `build_spec.py` to emit namespace JSON.
"""

# Section prefix codes are baked into WSTG and stable across versions.
SECTION_PREFIXES = {
    1:  ("INFO", "information gathering"),
    2:  ("CONF", "configuration and deployment management"),
    3:  ("IDNT", "identity management"),
    4:  ("ATHN", "authentication"),
    5:  ("ATHZ", "authorization"),
    6:  ("SESS", "session management"),
    7:  ("INPV", "input validation"),
    8:  ("ERRH", "error handling"),
    9:  ("CRYP", "cryptography"),
    10: ("BUSL", "business logic"),
    11: ("CLNT", "client-side"),
    12: ("APIT", "api"),
}

# Page slug roots so we can rebuild the canonical OWASP URL for each entry.
SECTION_SLUGS = {
    1:  "01-Information_Gathering",
    2:  "02-Configuration_and_Deployment_Management_Testing",
    3:  "03-Identity_Management_Testing",
    4:  "04-Authentication_Testing",
    5:  "05-Authorization_Testing",
    6:  "06-Session_Management_Testing",
    7:  "07-Input_Validation_Testing",
    8:  "08-Testing_for_Error_Handling",
    9:  "09-Testing_for_Weak_Cryptography",
    10: "10-Business_Logic_Testing",
    11: "11-Client-side_Testing",
    12: "12-API_Testing",
}

# Each tuple: (section, sub, sub_sub, title, page_slug, level, static_applicable)
#   section: top-level section number (1-12)
#   sub: test number within the section (1-N)
#   sub_sub: sub-test number, or None if not a sub-test
#   page_slug: filename portion of the URL on owasp.org / GitHub
#   level: 1, 2, or 3
#   static_applicable: True if reviewable from source code alone
#
# Notes on level assignments:
#   - Baseline (1): things every web app should do — input validation on
#     dangerous sinks, session cookie flags, TLS, error handling, basic authz.
#   - Standard (2): applies to apps with auth, sessions, sensitive data —
#     MFA, OAuth, JWT, rate limiting, CORS hardening, etc.
#   - Advanced (3): niche tech (Flash, RIA, MS Access), specialist conditions
#     (subdomain takeover, padding oracle, session puzzling).
#
# Notes on static_applicable:
#   False = the test inherently requires a running target (DNS reconnaissance,
#           live fingerprinting, network probing, account-lockout testing,
#           runtime session hijack). These are excluded from the static audit
#           but kept in the catalog for completeness and future runtime audits.

WSTG_TESTS = [
    # 4.1 Information Gathering ----------------------------------------------
    (1, 1, None, "Conduct Search Engine Discovery Reconnaissance for Information Leakage",
     "01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage", 2, False),
    (1, 2, None, "Fingerprint Web Server",
     "02-Fingerprint_Web_Server", 2, False),
    (1, 3, None, "Review Webserver Metafiles for Information Leakage",
     "03-Review_Webserver_Metafiles_for_Information_Leakage", 2, True),
    (1, 4, None, "Attack Surface Identification",
     "04-Attack_Surface_Identification", 2, True),
    (1, 5, None, "Review Web Page Content for Information Leakage",
     "05-Review_Web_Page_Content_for_Information_Leakage", 1, True),
    (1, 6, None, "Identify Application Entry Points",
     "06-Identify_Application_Entry_Points", 1, True),
    (1, 7, None, "Map Execution Paths Through Application",
     "07-Map_Execution_Paths_Through_Application", 2, True),
    (1, 8, None, "Fingerprint Web Application Framework",
     "08-Fingerprint_Web_Application_Framework", 3, False),
    (1, 9, None, "Fingerprint Web Application",
     "09-Fingerprint_Web_Application", 3, False),
    (1, 10, None, "Map Application Architecture",
     "10-Map_Application_Architecture", 2, True),

    # 4.2 Configuration and Deployment Management ----------------------------
    (2, 1, None, "Test Network Infrastructure Configuration",
     "01-Test_Network_Infrastructure_Configuration", 2, False),
    (2, 2, None, "Test Application Platform Configuration",
     "02-Test_Application_Platform_Configuration", 1, True),
    (2, 3, None, "Test File Extensions Handling for Sensitive Information",
     "03-Test_File_Extensions_Handling_for_Sensitive_Information", 2, True),
    (2, 4, None, "Review Old Backup and Unreferenced Files for Sensitive Information",
     "04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information", 2, True),
    (2, 5, None, "Enumerate Infrastructure and Application Admin Interfaces",
     "05-Enumerate_Infrastructure_and_Application_Admin_Interfaces", 2, True),
    (2, 6, None, "Test HTTP Methods",
     "06-Test_HTTP_Methods", 1, True),
    (2, 7, None, "Test HTTP Strict Transport Security",
     "07-Test_HTTP_Strict_Transport_Security", 1, True),
    (2, 8, None, "Test RIA Cross Domain Policy",
     "08-Test_RIA_Cross_Domain_Policy", 3, True),
    (2, 9, None, "Test File Permission",
     "09-Test_File_Permission", 2, True),
    (2, 10, None, "Test for Subdomain Takeover",
     "10-Test_for_Subdomain_Takeover", 3, False),
    (2, 11, None, "Test Cloud Storage",
     "11-Test_Cloud_Storage", 2, False),
    (2, 12, None, "Test for Content Security Policy",
     "12-Test_for_Content_Security_Policy", 1, True),
    (2, 13, None, "Test for Path Confusion",
     "13-Test_for_Path_Confusion", 2, True),
    (2, 14, None, "Test Other HTTP Security Header Misconfigurations",
     "14-Test_Other_HTTP_Security_Header_Misconfigurations", 1, True),

    # 4.3 Identity Management ------------------------------------------------
    (3, 1, None, "Test Role Definitions",
     "01-Test_Role_Definitions", 2, True),
    (3, 2, None, "Test User Registration Process",
     "02-Test_User_Registration_Process", 2, True),
    (3, 3, None, "Test Account Provisioning Process",
     "03-Test_Account_Provisioning_Process", 2, True),
    (3, 4, None, "Testing for Account Enumeration and Guessable User Account",
     "04-Testing_for_Account_Enumeration_and_Guessable_User_Account", 2, True),
    (3, 5, None, "Testing for Weak or Unenforced Username Policy",
     "05-Testing_for_Weak_or_Unenforced_Username_Policy", 2, True),

    # 4.4 Authentication -----------------------------------------------------
    (4, 1, None, "Testing for Credentials Transported over an Encrypted Channel",
     "01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel", 1, True),
    (4, 2, None, "Testing for Default Credentials",
     "02-Testing_for_Default_Credentials", 1, True),
    (4, 3, None, "Testing for Weak Lock Out Mechanism",
     "03-Testing_for_Weak_Lock_Out_Mechanism", 2, False),
    (4, 4, None, "Testing for Bypassing Authentication Schema",
     "04-Testing_for_Bypassing_Authentication_Schema", 1, True),
    (4, 5, None, "Testing for Vulnerable Remember Password",
     "05-Testing_for_Vulnerable_Remember_Password", 2, True),
    (4, 6, None, "Testing for Browser Cache Weaknesses",
     "06-Testing_for_Browser_Cache_Weaknesses", 2, True),
    (4, 7, None, "Testing for Weak Authentication Methods",
     "07-Testing_for_Weak_Authentication_Methods", 1, True),
    (4, 8, None, "Testing for Weak Security Question Answer",
     "08-Testing_for_Weak_Security_Question_Answer", 3, True),
    (4, 9, None, "Testing for Weak Password Change or Reset Functionalities",
     "09-Testing_for_Weak_Password_Change_or_Reset_Functionalities", 1, True),
    (4, 10, None, "Testing for Weaker Authentication in Alternative Channel",
     "10-Testing_for_Weaker_Authentication_in_Alternative_Channel", 2, True),
    (4, 11, None, "Testing Multi-Factor Authentication",
     "11-Testing_Multi-Factor_Authentication", 2, True),

    # 4.5 Authorization ------------------------------------------------------
    (5, 1, None, "Testing Directory Traversal File Include",
     "01-Testing_Directory_Traversal_File_Include", 1, True),
    (5, 2, None, "Testing for Bypassing Authorization Schema",
     "02-Testing_for_Bypassing_Authorization_Schema", 1, True),
    (5, 3, None, "Testing for Privilege Escalation",
     "03-Testing_for_Privilege_Escalation", 1, True),
    (5, 4, None, "Testing for Insecure Direct Object References",
     "04-Testing_for_Insecure_Direct_Object_References", 1, True),
    (5, 5, None, "Testing for OAuth Weaknesses",
     "05-Testing_for_OAuth_Weaknesses", 2, True),
    (5, 5, 1, "Testing for OAuth Authorization Server Weaknesses",
     "05.1-Testing_for_OAuth_Authorization_Server_Weaknesses", 2, True),
    (5, 5, 2, "Testing for OAuth Client Weaknesses",
     "05.2-Testing_for_OAuth_Client_Weaknesses", 2, True),

    # 4.6 Session Management -------------------------------------------------
    (6, 1, None, "Testing for Session Management Schema",
     "01-Testing_for_Session_Management_Schema", 1, True),
    (6, 2, None, "Testing for Cookies Attributes",
     "02-Testing_for_Cookies_Attributes", 1, True),
    (6, 3, None, "Testing for Session Fixation",
     "03-Testing_for_Session_Fixation", 1, True),
    (6, 4, None, "Testing for Exposed Session Variables",
     "04-Testing_for_Exposed_Session_Variables", 2, True),
    (6, 5, None, "Testing for Cross Site Request Forgery",
     "05-Testing_for_Cross_Site_Request_Forgery", 1, True),
    (6, 6, None, "Testing for Logout Functionality",
     "06-Testing_for_Logout_Functionality", 1, True),
    (6, 7, None, "Testing Session Timeout",
     "07-Testing_Session_Timeout", 1, True),
    (6, 8, None, "Testing for Session Puzzling",
     "08-Testing_for_Session_Puzzling", 3, True),
    (6, 9, None, "Testing for Session Hijacking",
     "09-Testing_for_Session_Hijacking", 2, False),
    (6, 10, None, "Testing JSON Web Tokens",
     "10-Testing_JSON_Web_Tokens", 2, True),
    (6, 11, None, "Testing for Concurrent Sessions",
     "11-Testing_for_Concurrent_Sessions", 2, True),

    # 4.7 Input Validation ---------------------------------------------------
    (7, 1, None, "Testing for Reflected Cross Site Scripting",
     "01-Testing_for_Reflected_Cross_Site_Scripting", 1, True),
    (7, 2, None, "Testing for Stored Cross Site Scripting",
     "02-Testing_for_Stored_Cross_Site_Scripting", 1, True),
    (7, 3, None, "Testing for HTTP Verb Tampering",
     "03-Testing_for_HTTP_Verb_Tampering", 1, True),
    (7, 4, None, "Testing for HTTP Parameter Pollution",
     "04-Testing_for_HTTP_Parameter_Pollution", 2, True),
    (7, 5, None, "Testing for SQL Injection",
     "05-Testing_for_SQL_Injection", 1, True),
    (7, 5, 1, "Testing for Oracle",
     "05.1-Testing_for_Oracle", 2, True),
    (7, 5, 2, "Testing for MySQL",
     "05.2-Testing_for_MySQL", 2, True),
    (7, 5, 3, "Testing for SQL Server",
     "05.3-Testing_for_SQL_Server", 2, True),
    (7, 5, 4, "Testing PostgreSQL",
     "05.4-Testing_PostgreSQL", 2, True),
    (7, 5, 5, "Testing for MS Access",
     "05.5-Testing_for_MS_Access", 3, True),
    (7, 5, 6, "Testing for NoSQL Injection",
     "05.6-Testing_for_NoSQL_Injection", 2, True),
    (7, 5, 7, "Testing for ORM Injection",
     "05.7-Testing_for_ORM_Injection", 2, True),
    (7, 5, 8, "Testing for Client-side",
     "05.8-Testing_for_Client-side", 2, True),
    (7, 6, None, "Testing for LDAP Injection",
     "06-Testing_for_LDAP_Injection", 2, True),
    (7, 7, None, "Testing for XML Injection",
     "07-Testing_for_XML_Injection", 2, True),
    (7, 8, None, "Testing for SSI Injection",
     "08-Testing_for_SSI_Injection", 3, True),
    (7, 9, None, "Testing for XPath Injection",
     "09-Testing_for_XPath_Injection", 2, True),
    (7, 10, None, "Testing for IMAP SMTP Injection",
     "10-Testing_for_IMAP_SMTP_Injection", 2, True),
    (7, 11, None, "Testing for Code Injection",
     "11-Testing_for_Code_Injection", 1, True),
    (7, 11, 1, "Testing for File Inclusion",
     "11.1-Testing_for_File_Inclusion", 1, True),
    (7, 12, None, "Testing for Command Injection",
     "12-Testing_for_Command_Injection", 1, True),
    (7, 13, None, "Testing for Format String Injection",
     "13-Testing_for_Format_String_Injection", 2, True),
    (7, 14, None, "Testing for Incubated Vulnerability",
     "14-Testing_for_Incubated_Vulnerability", 3, True),
    (7, 15, None, "Testing for HTTP Response Splitting",
     "15-Testing_for_HTTP_Response_Splitting", 2, True),
    (7, 16, None, "Testing for HTTP Request Smuggling",
     "16-Testing_for_HTTP_Request_Smuggling", 2, True),
    (7, 17, None, "Testing for Host Header Injection",
     "17-Testing_for_Host_Header_Injection", 2, True),
    (7, 18, None, "Testing for Server-side Template Injection",
     "18-Testing_for_Server-side_Template_Injection", 2, True),
    (7, 19, None, "Testing for Server-Side Request Forgery",
     "19-Testing_for_Server-Side_Request_Forgery", 1, True),
    (7, 20, None, "Testing for Mass Assignment",
     "20-Testing_for_Mass_Assignment", 2, True),
    (7, 21, None, "Testing for CSV Injection",
     "21-Testing_for_CSV_Injection", 3, True),

    # 4.8 Error Handling -----------------------------------------------------
    (8, 1, None, "Testing for Improper Error Handling",
     "01-Testing_For_Improper_Error_Handling", 1, True),
    (8, 2, None, "Testing for Stack Traces",
     "02-Testing_for_Stack_Traces", 1, True),

    # 4.9 Cryptography -------------------------------------------------------
    (9, 1, None, "Testing for Weak Transport Layer Security",
     "01-Testing_for_Weak_Transport_Layer_Security", 1, False),
    (9, 2, None, "Testing for Padding Oracle",
     "02-Testing_for_Padding_Oracle", 3, True),
    (9, 3, None, "Testing for Sensitive Information Sent via Unencrypted Channels",
     "03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels", 1, True),
    (9, 4, None, "Testing for Weak Cryptographic Primitives",
     "04-Testing_for_Weak_Cryptographic_Primitives", 1, True),

    # 4.10 Business Logic ----------------------------------------------------
    (10, 1, None, "Test Business Logic Data Validation",
     "01-Test_Business_Logic_Data_Validation", 2, True),
    (10, 2, None, "Test Ability to Forge Requests",
     "02-Test_Ability_to_Forge_Requests", 2, True),
    (10, 3, None, "Test Integrity Checks",
     "03-Test_Integrity_Checks", 2, True),
    (10, 4, None, "Test for Process Timing",
     "04-Test_for_Process_Timing", 3, True),
    (10, 5, None, "Test Number of Times a Function Can Be Used Limits",
     "05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits", 2, True),
    (10, 6, None, "Testing for the Circumvention of Work Flows",
     "06-Testing_for_the_Circumvention_of_Work_Flows", 2, True),
    (10, 7, None, "Test Defenses Against Application Misuse",
     "07-Test_Defenses_Against_Application_Misuse", 3, True),
    (10, 8, None, "Test Upload of Unexpected File Types",
     "08-Test_Upload_of_Unexpected_File_Types", 2, True),
    (10, 9, None, "Test Upload of Malicious Files",
     "09-Test_Upload_of_Malicious_Files", 2, True),
    (10, 10, None, "Test Payment Functionality",
     "10-Test-Payment-Functionality", 3, True),

    # 4.11 Client-side -------------------------------------------------------
    (11, 1, None, "Testing for DOM-Based Cross Site Scripting",
     "01-Testing_for_DOM-based_Cross_Site_Scripting", 1, True),
    (11, 1, 1, "Testing for Self DOM Based Cross-Site Scripting",
     "01.1-Testing_for_Self_DOM_Based_Cross_Site_Scripting", 3, True),
    (11, 2, None, "Testing for JavaScript Execution",
     "02-Testing_for_JavaScript_Execution", 2, True),
    (11, 3, None, "Testing for HTML Injection",
     "03-Testing_for_HTML_Injection", 2, True),
    (11, 4, None, "Testing for Client-side URL Redirect",
     "04-Testing_for_Client-side_URL_Redirect", 2, True),
    (11, 5, None, "Testing for CSS Injection",
     "05-Testing_for_CSS_Injection", 3, True),
    (11, 6, None, "Testing for Client-side Resource Manipulation",
     "06-Testing_for_Client-side_Resource_Manipulation", 2, True),
    (11, 7, None, "Testing Cross Origin Resource Sharing",
     "07-Testing_Cross_Origin_Resource_Sharing", 1, True),
    (11, 8, None, "Testing for Cross Site Flashing",
     "08-Testing_for_Cross_Site_Flashing", 3, True),
    (11, 9, None, "Testing for Clickjacking",
     "09-Testing_for_Clickjacking", 1, True),
    (11, 10, None, "Testing WebSockets",
     "10-Testing_WebSockets", 2, True),
    (11, 11, None, "Testing Web Messaging",
     "11-Testing_Web_Messaging", 2, True),
    (11, 12, None, "Testing Browser Storage",
     "12-Testing_Browser_Storage", 2, True),
    (11, 13, None, "Testing for Cross Site Script Inclusion",
     "13-Testing_for_Cross_Site_Script_Inclusion", 3, True),
    (11, 14, None, "Testing for Reverse Tabnabbing",
     "14-Testing_for_Reverse_Tabnabbing", 2, True),
    (11, 15, None, "Testing for Client-side Template Injection",
     "15-Testing_for_Client-Side_Template_Injection", 2, True),

    # 4.12 API ---------------------------------------------------------------
    (12, 1, None, "API Reconnaissance",
     "01-API_Reconnaissance", 2, True),
    (12, 2, None, "API Broken Object Level Authorization",
     "02-API_Broken_Object_Level_Authorization", 1, True),
    (12, 3, None, "Testing for Excessive Data Exposure",
     "03-Testing_for_Excessive_Data_Exposure", 1, True),
    (12, 4, None, "API Broken Function Level Authorization",
     "04-API_Broken_Function_Level_Authorization", 1, True),
    (12, 99, None, "Testing GraphQL",
     "99-Testing_GraphQL", 2, True),
]


# Curated cross-references to other specs in the multi-spec architecture.
# Maps WSTG ID → {"asvs": [...], "cwe-top-25": [...], "api-top-10": [...]}.
#
# These are high-confidence mappings only. WSTG itself does not publish a
# canonical cross-ref table inside each test page; the v4.x guide had a
# cross-reference appendix and OWASP maintains a separate WSTG-ASVS mapping
# project, but the latest/ tree we're sourcing from has stripped those.
#
# Strategy: include a mapping only when the relationship is unambiguous (the
# WSTG test and the foreign-spec requirement describe the same vulnerability
# with no scope mismatch). The consolidator's cross-spec dedup will collapse
# findings; missing entries just mean we don't get cross-spec dedup for that
# pairing — they don't break anything.
#
# ASVS IDs use the v5.0 numbering. CWE IDs use the 2024 Top 25. API Top 10
# IDs use 2023 (API1 .. API10).
CROSS_REFERENCES = {
    # Configuration & Deployment
    "WSTG-CONF-06":  {"asvs": ["13.1.4"]},
    "WSTG-CONF-07":  {"asvs": ["14.4.5", "9.1.1"]},
    "WSTG-CONF-12":  {"asvs": ["14.4.3"]},
    "WSTG-CONF-14":  {"asvs": ["14.4.1", "14.4.2", "14.4.4", "14.4.6", "14.4.7"]},

    # Authentication
    "WSTG-ATHN-01":  {"asvs": ["2.2.5", "9.1.1"]},
    "WSTG-ATHN-02":  {"asvs": ["2.1.1", "2.1.2"]},
    "WSTG-ATHN-04":  {"asvs": ["2.1.1"]},
    "WSTG-ATHN-09":  {"asvs": ["2.5.1", "2.5.2", "2.5.3", "2.5.4"]},
    "WSTG-ATHN-11":  {"asvs": ["2.7.1", "2.7.2", "2.8.1"]},

    # Authorization
    "WSTG-ATHZ-01":  {"asvs": ["12.3.1", "12.3.2"], "cwe-top-25": ["CWE-22"]},
    "WSTG-ATHZ-02":  {"asvs": ["4.1.1", "4.1.2"], "api-top-10": ["API5"]},
    "WSTG-ATHZ-03":  {"asvs": ["4.1.3", "4.2.1"], "cwe-top-25": ["CWE-269"], "api-top-10": ["API5"]},
    "WSTG-ATHZ-04":  {"asvs": ["4.2.1"], "cwe-top-25": ["CWE-639"], "api-top-10": ["API1"]},

    # Session Management
    "WSTG-SESS-02":  {"asvs": ["3.4.1", "3.4.2", "3.4.3"]},
    "WSTG-SESS-03":  {"asvs": ["3.2.1"], "cwe-top-25": ["CWE-384"]},
    "WSTG-SESS-05":  {"asvs": ["4.2.2", "13.2.3"], "cwe-top-25": ["CWE-352"]},
    "WSTG-SESS-07":  {"asvs": ["3.3.1", "3.3.2"]},
    "WSTG-SESS-10":  {"asvs": ["3.5.1", "3.5.2", "3.5.3"]},

    # Input Validation
    "WSTG-INPV-01":  {"asvs": ["5.3.3"], "cwe-top-25": ["CWE-79"], "api-top-10": ["API8"]},
    "WSTG-INPV-02":  {"asvs": ["5.3.3"], "cwe-top-25": ["CWE-79"], "api-top-10": ["API8"]},
    "WSTG-INPV-05":  {"asvs": ["5.3.4", "5.3.5"], "cwe-top-25": ["CWE-89"], "api-top-10": ["API8"]},
    "WSTG-INPV-06":  {"asvs": ["5.3.7"], "cwe-top-25": ["CWE-90"]},
    "WSTG-INPV-07":  {"asvs": ["5.5.1", "5.5.2"], "cwe-top-25": ["CWE-91", "CWE-611"]},
    "WSTG-INPV-11":  {"asvs": ["5.2.4"], "cwe-top-25": ["CWE-94"]},
    "WSTG-INPV-12":  {"asvs": ["5.3.8"], "cwe-top-25": ["CWE-78"]},
    "WSTG-INPV-18":  {"asvs": ["5.2.5"], "cwe-top-25": ["CWE-1336"]},
    "WSTG-INPV-19":  {"asvs": ["12.6.1"], "cwe-top-25": ["CWE-918"], "api-top-10": ["API7"]},
    "WSTG-INPV-20":  {"asvs": ["5.1.2"], "cwe-top-25": ["CWE-915"], "api-top-10": ["API6"]},

    # Error Handling
    "WSTG-ERRH-01":  {"asvs": ["7.4.1"], "cwe-top-25": ["CWE-209"]},
    "WSTG-ERRH-02":  {"asvs": ["7.4.1"], "cwe-top-25": ["CWE-209"]},

    # Cryptography
    "WSTG-CRYP-01":  {"asvs": ["9.1.2", "9.1.3"], "cwe-top-25": ["CWE-295"]},
    "WSTG-CRYP-03":  {"asvs": ["9.1.1"], "cwe-top-25": ["CWE-319"]},
    "WSTG-CRYP-04":  {"asvs": ["6.2.1", "6.2.2", "6.2.3"], "cwe-top-25": ["CWE-327"]},

    # Client-side
    "WSTG-CLNT-01":  {"asvs": ["5.3.3"], "cwe-top-25": ["CWE-79"]},
    "WSTG-CLNT-07":  {"asvs": ["14.5.3"]},
    "WSTG-CLNT-09":  {"asvs": ["14.4.6"]},

    # API
    "WSTG-APIT-02":  {"asvs": ["4.1.1", "4.2.1"], "api-top-10": ["API1"]},
    "WSTG-APIT-03":  {"asvs": ["8.1.6"], "api-top-10": ["API3"]},
    "WSTG-APIT-04":  {"asvs": ["4.1.2"], "api-top-10": ["API5"]},
}


def derive_id(section: int, sub: int, sub_sub):
    """Section path → WSTG ID. e.g. (7, 5, None) → 'WSTG-INPV-05'."""
    prefix = SECTION_PREFIXES[section][0]
    if sub_sub is None:
        return f"WSTG-{prefix}-{sub:02d}"
    return f"WSTG-{prefix}-{sub:02d}.{sub_sub}"


def parent_id(section: int, sub: int, sub_sub):
    """Sub-tests get a parent_id pointing at their top-level test."""
    if sub_sub is None:
        return None
    return derive_id(section, sub, None)


def canonical_url(section: int, page_slug: str) -> str:
    """Public URL on owasp.org for the test page (also resolvable to the
    GitHub source markdown by swapping the host)."""
    base = ("https://owasp.org/www-project-web-security-testing-guide/"
            "latest/4-Web_Application_Security_Testing")
    return f"{base}/{SECTION_SLUGS[section]}/{page_slug}"


def github_url(section: int, page_slug: str) -> str:
    """URL to the markdown source in the OWASP/wstg... repo."""
    base = ("https://github.com/OWASP/www-project-web-security-testing-guide/"
            "blob/master/latest/4-Web_Application_Security_Testing")
    return f"{base}/{SECTION_SLUGS[section]}/{page_slug}.md"


def category(section: int) -> str:
    return SECTION_PREFIXES[section][1]
