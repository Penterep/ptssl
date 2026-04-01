"""
Supported cipher algorithm – detects servers cipher algorithms and flags weak algorithms.
Analyses the cipher algorithm item of a testssl JSON report to tell
whether the target server offers weak cipher algorithms.

Contains:
- ALG class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib)
"""

from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint
from helpers.descriptions import DESCRIPTION_MAP

__TESTLABEL__ = "Testing for cipher suites algorithm:"


class ALG:
    """
    ALG checks for weak cipher algorithms.

    It consumes the JSON output from testssl and check if weak cipher algorithm is found.
    """
    ERROR_NUM = -1
    cert_list = ["sslv2", "sslv3", "tls1", "tls1_1", "tls1_2", "tls1_3"]
    cert_print_list = ["SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]


    def __init__(self, args: object, ptjsonlib: object, helpers: object, testssl_result: dict) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.testssl_result = testssl_result

    def _find_section_sa(self) -> int:
        """
        Runs through JSON file and finds ALG item.
        """
        id_number = 0
        for item in self.testssl_result:
            if item["id"].startswith("cipher_order"):
                return id_number
            id_number += 1
        return self.ERROR_NUM

    def _print_test_result(self) -> None:
        """
        Finds starting id of "cipher algorithms" section.
        Goes through the section using list of IDs and prints out potential vulnerabilities.
        1) OK
        2) INFO - prints warning information
        3) VULN - prints out vulnerabilities
        """
        id_section = self._find_section_sa()
        if id_section == self.ERROR_NUM:
            self.ptjsonlib.end_error("testssl could not provide Cipher algorithms section", self.args.json)
            return

        secure_algs = []
        weak_algs = []

        item = self.testssl_result[id_section]
        current = id_section
        for i in range(6):
            if not item["id"].startswith("cipher_order-") or not item["id"].endswith(self.cert_list[i]):
                ptprint(f"{self.cert_print_list[i]}", "TEXT", not self.args.json, indent=4)
                ptprint("-", "TEXT", not self.args.json, indent=8)
                continue

            ptprint(f"{self.cert_print_list[i]}  order:{item['finding']}", item['severity'], not self.args.json, indent=4)
            current += 1
            item = self.testssl_result[current]

            while not item["id"].startswith("cipherorder"):
                alg_name = item['finding'].split(maxsplit=2)[2].split()[0]
                if item["severity"] == "OK":
                    ptprint(f"{alg_name}", "OK", not self.args.json, indent=8)
                    secure_algs.append(alg_name)
                else:
                    ptprint(f"{alg_name}", "WARNING", not self.args.json, indent=8)
                    weak_algs.append(alg_name)
                current += 1
                item = self.testssl_result[current]
            current += 1
            item = self.testssl_result[current]

        if weak_algs:
            description = ""
            if secure_algs:
                description += "Secure algorithms: " + ", ".join(secure_algs)
            if secure_algs and weak_algs:
                description += "\r\n"
            description += "Insecure algorithms: " + ", ".join(weak_algs)
            self.ptjsonlib.add_properties({"description": description})
            self.ptjsonlib.add_vulnerability("PTV-WEB-CRYPT-ALGWEAK")
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
    """Entry point for running the ALG module (Cipher Algorithms)."""
    ALG(args, ptjsonlib, helpers, testssl_result).run()