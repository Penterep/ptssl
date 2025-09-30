"""
Test Server Defaults – check server defaults and flags vulnerabilities.
Analyses the JSON report to flag vulnerabilities.

Contains:
- TSD class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib)
"""

from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Testing server defaults:"


class TSD:
    """
    TSD checks whether the server have vulnerabilities:
        - weak sign algorithm
        - weak key size
        - certification Authority chain validity
        - certificate trust status
        - certificate expiration
        - OCSP stapling
        - certificate transparency

    It consumes the JSON output from testssl and flags vulnerabilities.
    """

    DEFAULT_SEC_LEN = 36
    ERROR_NUM = -1
    CERT_SIG_ALGO = 0
    CERT_KEY_SIZE = 1
    CERT_TRUST = 12
    CERT_CHAIN_OF_TRUST = 13
    CERT_NOT_BEFORE = 17
    CERT_NOT_AFTER  = 18
    OCSP_STAPLING = 22
    CERT_TRANSPARENCY = 25

    def __init__(self, args: object, ptjsonlib: object, helpers: object, testssl_result: dict) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.testssl_result = testssl_result

    def _find_section_tsd(self) -> int:
        """
        Runs through JSON file and finds strat of "server defaults" section.
        """
        id_number = 0
        for item in self.testssl_result:
            if item["id"] == "cert_signatureAlgorithm":
                return id_number
            id_number += 1
        return self.ERROR_NUM

    def _print_test_result(self) -> None:
        """
        Finds starting id of "server defaults" section.
        Goes through the section using list of IDs and prints out potential vulnerabilities.
        1) OK
        2) INFO - prints warning information
        3) VULN - prints out vulnerabilities
        """
        id_section = self._find_section_tsd()
        if id_section == self.ERROR_NUM:
            self.ptjsonlib.end_error("testssl could not provide server's default section", self.args.json)
            return

        id_of_vulnerability = [self.CERT_SIG_ALGO, self.CERT_KEY_SIZE, self.CERT_CHAIN_OF_TRUST, self.CERT_TRUST,
                               self.CERT_NOT_BEFORE, self.CERT_NOT_AFTER, self.OCSP_STAPLING, self.CERT_TRANSPARENCY]

        cert_vuln_counter = 0

        for vuln in id_of_vulnerability:
            item = self.testssl_result[vuln + id_section]
            if item["severity"] in ["OK", "INFO"]:
                ptprint(f"{item["id"]:<25}:  {item["finding"]}", "OK", not self.args.json, indent=4)
                """
                elif item["severity"] == "INFO":
                    if item["id"] == "cert_notAfter":
                        ptprint(f"{"cert_expiration":<25}:  {item["finding"]}", "WARNING", not self.args.json, indent=4)
                        cert_vuln_counter += 1
                        self.ptjsonlib.add_vulnerability(f'PTV-WEB-MISC-{''.join(ch for ch in item["id"] if ch.isalnum()).upper()}')
                    if item["id"] == "cert_keySize":
                        ptprint(f"{item["id"]:<25}:  {item["finding"]}", "OK", not self.args.json, indent=4)
                    else:
                        ptprint(f"{item["id"]:<25}:  {item["finding"]}", "WARNING", not self.args.json, indent=4)
                        cert_vuln_counter += 1
                        self.ptjsonlib.add_vulnerability(
                            f'PTV-WEB-MISC-{''.join(ch for ch in item["id"] if ch.isalnum()).upper()}')
                """
            else:
                ptprint(f"{item["id"]:<25}:  {item["finding"]}", "VULN", not self.args.json, indent=4)
                cert_vuln_counter += 1
                self.ptjsonlib.add_vulnerability(
                    f'PTV-WEB-MISC-{''.join(ch for ch in item["id"] if ch.isalnum()).upper()}')

        if cert_vuln_counter > 0:
            ptprint("The server is vulnerable to fake certificates abuse", "VULN", not self.args.json, indent=4)
        else:
            ptprint("The server greatly reduces the risk to fake certificates abuse", "OK",not self.args.json, indent=4)

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
    """Entry point for running the TSD module (Test Server Defaults)."""
    TSD(args, ptjsonlib, helpers, testssl_result).run()