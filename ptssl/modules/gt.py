"""
Grease Test – checks for bugs.
Analyses the Grease item of a testssl JSON report to tell
whether the target server have bugs or not.

Contains:
- GT class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib)
"""

from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Testing for bugs:"


class GT:
    """
    GT checks for bugs.

    It consumes the JSON output from testssl and check if bugs were detected.
    """
    ERROR_NUM = -1
    DESCRIPTION_MAP = {}


    def __init__(self, args: object, ptjsonlib: object, helpers: object, testssl_result: dict) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.testssl_result = testssl_result

    def _find_section_g(self) -> int:
        """
        Runs through JSON file and finds Grease item.
        """
        id_number = 0
        for item in self.testssl_result:
            if item["id"] == "GREASE":
                return id_number
            id_number += 1
        return self.ERROR_NUM

    def _print_test_result(self) -> None:
        """
        Finds Greasse item.
        Flags if bugs were detected.
        1) OK
        2) INFO - prints warning information
        3) VULN - prints out vulnerabilities
        """
        id_grease = self._find_section_g()
        if id_grease == self.ERROR_NUM:
            ptprint("testssl could not provide grease section", "WARNING", not self.args.json, indent=4)
            return
        item = self.testssl_result[id_grease]

        # Lookup friendly name / description (fallback to raw ID)
        desc_entry = self.DESCRIPTION_MAP.get(item["id"], {})
        display_name = desc_entry.get("name", item["id"])

        # Print main status
        if item["severity"] == "OK":
            ptprint(f"{display_name:<8}  {item['finding']}", "OK", not self.args.json, indent=4)
        elif item["severity"] == "INFO":
            ptprint(f"{display_name:<8}  {item['finding']}", "WARNING", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                f"PTV-WEB-MISC-{''.join(ch for ch in item['id'] if ch.isalnum()).upper()}"
            )
        else:
            ptprint(f"{display_name:<8}  {item['finding']}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                f"PTV-WEB-MISC-{''.join(ch for ch in item['id'] if ch.isalnum()).upper()}"
            )

        # Optional verbose description
        if self.args.verbose and "description" in desc_entry:
            ptprint(f"↳ {desc_entry['description']}", "ADDITIONS", not self.args.json, indent=6, colortext=True)



    def run(self) -> None:
        """
        Prints out the test label
        Execute the testssl report function.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        self._print_test_result()
        return


def run(args, ptjsonlib, helpers, testssl_result):
    """Entry point for running the GT module (Grease Test)."""
    GT(args, ptjsonlib, helpers, testssl_result).run()