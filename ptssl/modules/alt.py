"""
Alternative Domain Names – detects when server has alternative domain names.
Analyses the alt_name item of a testssl JSON report to tell
whether the target server has alternative domain names.

Contains:
- ALT class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib)
"""

from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint
from helpers.descriptions import DESCRIPTION_MAP

__TESTLABEL__ = "Testing for Certificate Alternative Domain Names:"


class ALT:
    """
    ALT checks whether the server has alternative domain names.

    It consumes the JSON output from testssl and check if server has alternative domain names.
    """
    ERROR_NUM = -1


    def __init__(self, args: object, ptjsonlib: object, helpers: object, testssl_result: dict) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.testssl_result = testssl_result

    def _find_section_alt(self) -> int:
        """
        Runs through JSON file and finds alt_name item.
        """
        id_number = 0
        for item in self.testssl_result:
            if item["id"] == "cert_subjectAltName":
                return id_number
            id_number += 1
        return self.ERROR_NUM

    def _print_test_result(self) -> None:
        """
        Finds alt_name item.
        Flags if the server has alternative domain names.
        1) OK
        2) INFO - prints warning information
        3) VULN - prints out vulnerabilities
        """
        id_alt = self._find_section_alt()
        if id_alt == self.ERROR_NUM:
            ptprint("testssl could not provide Alternative domain name section", "WARNING", not self.args.json, indent=4)
            return
        item = self.testssl_result[id_alt]

        # Lookup friendly name / description (fallback to raw ID)
        desc_entry = DESCRIPTION_MAP.get(item["id"], {})
        display_name = desc_entry.get("name", item["id"])

        # Print main status
        if item["severity"] == "OK":
            ptprint(f"{item['finding']}", "OK", not self.args.json, indent=4)
        else:
            for u in item["finding"].split():
                properties = {"name": u}
                n = self.ptjsonlib.create_node_object("web_app", properties)
                self.ptjsonlib.add_node(n)
                ptprint(f"{u}", "TEXT", not self.args.json, indent=4)


    def run(self) -> None:
        """
        Prints out the test label
        Execute the testssl report function.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        self._print_test_result()
        return


def run(args, ptjsonlib, helpers, testssl_result):
    """Entry point for running the ALT module (Alternative domain names)."""
    ALT(args, ptjsonlib, helpers, testssl_result).run()