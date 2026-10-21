"""
Encryption Test – checks whether the service offers encryption.
Uses the result of the encryption check done before the testssl scan to tell
whether the target service offers encrypted connection (implicit TLS or STARTTLS).

Contains:
- ENCRYPT class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib, helpers, testssl_result)
"""

from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint
from helpers.descriptions import DESCRIPTION_MAP

__TESTLABEL__ = "Testing if encryption is offered:"


class ENCRYPT:
    """
    ENCRYPT checks whether the service offers encryption.

    The encryption is detected by ptssl before the testssl scan and passed in helpers.encryption.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object, testssl_result: dict) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.testssl_result = testssl_result

    def _print_test_result(self) -> None:
        """
        Flags if the encryption is offered or not.
        1) OK - encryption is offered (implicit TLS or STARTTLS)
        2) VULN - encryption is not offered
        """
        # Lookup friendly name / description
        desc_entry = DESCRIPTION_MAP.get("encryption", {})
        display_name = desc_entry.get("name", "encryption")

        # Print main status
        if self.helpers.encryption:
            ptprint(f"{display_name:<43}  offered ({self.helpers.encryption})", "OK", not self.args.json, indent=4)
        else:
            ptprint(f"{display_name:<43}  not offered", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability("PTV-SVC-CRYPT-MISS")

        # Optional verbose description
        if self.args.verbose and "description" in desc_entry:
            ptprint(f"  {desc_entry['description']}", "ADDITIONS", not self.args.json, indent=6, colortext=True)


    def run(self) -> None:
        """
        Prints out the test label
        Execute the encryption report function.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        self._print_test_result()
        return


def run(args, ptjsonlib, helpers, testssl_result):
    """Entry point for running the ENCRYPT module (Encryption Test)."""
    ENCRYPT(args, ptjsonlib, helpers, testssl_result).run()
