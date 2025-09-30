"""
Cipher Test – detects insecure cipher use
Analyses the `ciphers` section of a testssl JSON report to tell
whether the target server still offers weak or vulnerable ciphers.

Contains:
- CT class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib)
"""

from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Testing for supported ciphers:"


class CT:
    """
    CT checks whether the server offers only strong and safe ciphers.

    It consumes the JSON output from testssl and flags any insecure or weak ciphers.
    """

    CIPHER_SEC_LEN = 8
    ERROR_NUM = -1

    def __init__(self, args: object, ptjsonlib: object, helpers: object, testssl_result: dict) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.testssl_result = testssl_result

    def _find_section_c(self) -> int:
        """
        Runs through JSON file and finds strat of cipher section.
        """
        id_number = 0
        for item in self.testssl_result:
            if item["id"] == "cipherlist_NULL":
                return id_number
            id_number += 1
        return self.ERROR_NUM

    def _print_test_result(self) -> None:
        """
        Finds starting id of cipher section.
        Goes through the section and prints out potential vulnerabilities.
        1) OK
        2) INFO - prints warning information
        3) VULN - prints out vulnerabilities
        """
        id_section = self._find_section_c()
        if id_section == self.ERROR_NUM:
            self.ptjsonlib.end_error("testssl could not provide cipher section", self.args.json)
            return

        for item in self.testssl_result[id_section:id_section + self.CIPHER_SEC_LEN]:
            if item["severity"] in ["OK", "INFO"]:
                ptprint(f"{item["id"]:<23}  {item["finding"]}", "OK", not self.args.json, indent=4)
            #elif item["severity"] == "INFO":
            #    ptprint(f"{item["id"]:<23}  {item["finding"]}", "WARNING", not self.args.json, indent=4)
            #    self.ptjsonlib.add_vulnerability(f'PTV-WEB-MISC-{''.join(ch for ch in item["id"] if ch.isalnum()).upper()}')
            else:
                ptprint(f"{item["id"]:<23}  {item["finding"]}", "VULN", not self.args.json, indent=4)
                self.ptjsonlib.add_vulnerability(f'PTV-WEB-MISC-{''.join(ch for ch in item["id"] if ch.isalnum()).upper()}')
        return


    def run(self) -> None:
        """
        Prints out the test label
        Execute the testssl report function.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        self._print_test_result()
        return


def run(args, ptjsonlib, helpers, testssl_result):
    """Entry point for running the CT module (Cipher Test)."""
    CT(args, ptjsonlib, helpers, testssl_result).run()