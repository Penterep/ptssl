"""
HTTP Strict Transport Security – checks if it is offered.
Analyses the HSTS item of a testssl JSON report to tell
whether the target server offers HSTS or not.

Contains:
- HSTS class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib)
"""

import re
from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Testing if HSTS is offered:"


class HSTS:
    """
    HSTS checks if HSTS is offered.

    It consumes the JSON output from testssl and check if HSTS is offered.
    """
    ERROR_NUM = -1

    def __init__(self, args: object, ptjsonlib: object, helpers: object, testssl_result: dict) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.testssl_result = testssl_result

    def run(self) -> None:
        """Run the HSTS module"""
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        try:
            response = self.helpers.http_client.send_request(self.args.url, allow_redirects=False)
            hsts_header = response.headers.get("strict-transport-security", None)
            if not hsts_header:
                ptprint(f"HSTS not offered", "VULN", not self.args.json, indent=4)
                self.ptjsonlib.add_vulnerability("PTV-WEB-HTTP-HSTSMIS")
            else:
                ptprint(f"HSTS offered", "OK", not self.args.json, indent=4)
                self.parse_hsts_header(hsts_header)
        except:
            ptprint(f"Error retrieving response for HSTS test", "ERROR", not self.args.json, indent=4)

    def parse_hsts_header(self, header_value: str) -> None:
        """
        Parses the `Strict-Transport-Security` header value and extracts the components: `max-age`,
        `includeSubDomains`, and `preload`. Calls `_print_result` to output the results.

        This method uses regular expressions to search for the presence of these components in
        the header value and updates the `attribs` dictionary accordingly.

        It also checks if the `max-age` is within a valid range and handles the `includeSubDomains`
        and `preload` attributes.

        :returns: None
        """

        # Regular expressions for HSTS header parameters
        max_age_pattern = re.compile(r'max-age=(\d+)')
        include_subdomains_pattern = re.compile(r'includeSubDomains')
        preload_pattern = re.compile(r'preload')

        self.attribs = {"max-age": None, "includeSubDomains": None, "preload": None}

        # Extracting max-age if present
        max_age_match = max_age_pattern.search(header_value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            self.attribs["max-age"] = max_age
        else:
            ptprint(f"missing max-age", "VULN", not self.args.json, indent=4)

        # Print max-age
        if self.attribs["max-age"]:
            value = self.attribs["max-age"]
            if value < 2592000:
                ptprint(f"max-age value is too small ({self.attribs['max-age']}), recommended value least 31536000", "VULN", not self.args.json, indent=4)
                self.ptjsonlib.add_vulnerability("PTV-WEB-HTTP-HSTSINV")
            elif value < 31536000:
                ptprint(f"max-age value is smaller than recommended ({self.attribs['max-age']}), recommended value least 31536000", "VULN", not self.args.json, indent=4)
                self.ptjsonlib.add_vulnerability("PTV-WEB-HTTP-HSTSINV")
            else:
                ptprint(f"max-age value offered ({self.attribs['max-age']})", "OK", not self.args.json, indent=4)

        # Checking for includeSubDomains and preload
        self.attribs["includeSubDomains"] = bool(include_subdomains_pattern.search(header_value))
        self.attribs["preload"] = bool(preload_pattern.search(header_value))

        if self.attribs["preload"]:
            ptprint(f"preload offered", "OK", not self.args.json, indent=4)
        else:
            ptprint(f"preload not offered", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability("PTV-WEB-HTTP-HSTSPL")

        if self.attribs["includeSubDomains"]:
            ptprint(f"includeSubdomains offered", "OK", not self.args.json, indent=4)
        else:
            ptprint(f"includeSubdomains not offered", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability("PTV-WEB-HTTP-HSTSSD")

def run(args, ptjsonlib, helpers, testssl_result):
    """Entry point for running the HSTS module (HTTP Strict Transport Security Test)."""
    HSTS(args, ptjsonlib, helpers, testssl_result).run()