"""
HTTP Redirection Test – checks for redirection from http to https.

Contains:
- HTTPR class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, helpers, testssl_result)
"""

from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Testing HTTP redirection:"


class HTTPR:
    """
    HTTPR checks for redirection from http to https.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object, testssl_result: dict) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.testssl_result = testssl_result

    def run(self) -> None:
        """Run the HTTPR module"""
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        try:
            http_url = "http://" + self.args.url.split("://")[-1]
            response = self.helpers.http_client.send_request(http_url, allow_redirects=False)
        except:
            ptprint(f"Error retrieving response for HTTPR test", "ERROR", not self.args.json, indent=4)
            return

        if response.is_redirect:
            if response.status_code in [301, 308]:
                ptprint(f"HTTP redirect to HTTPS:   OK", "OK", not self.args.json, indent=4)
            elif response.status_code in [302, 303, 307]:
                ptprint(f"HTTP redirect to HTTPS:   TEMPORARY (not fully secured)", "WARNING", not self.args.json, indent=4)
                self.ptjsonlib.add_vulnerability(f'PTV-WEB-CRYPT-REDIRSC')
        else:
            ptprint(f"HTTP redirect to HTTPS:   no redirection", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(f'PTV-WEB-CRYPT-REDIR')


def run(args, ptjsonlib, helpers, testssl_result):
    """Entry point for running the HTTPR module (HTTP Redirection Test)."""
    HTTPR(args, ptjsonlib, helpers, testssl_result).run()