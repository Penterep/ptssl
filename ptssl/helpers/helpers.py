"""
Helpers module for shared functionality used across test modules.
"""

import json
import os

from ptlibs.http.http_client import HttpClient
from ptlibs.ptprinthelper import ptprint

class Helpers:
    def __init__(self, args: object, ptjsonlib: object, http_client: object):
        """
        Helpers provides utility methods for loading definition files
        and making HTTP requests in a consistent way across modules.
        """
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = http_client
        # Mode in which target offers encryption ("implicit TLS" or "STARTTLS"), None if not offered
        self.encryption = None

    def fetch(self, url, allow_redirects=False):
        """
        Sends an HTTP GET request to the specified URL.

        Args:
            url (str): URL to fetch.
            allow_redirects (bool, optional): Whether to follow redirects. Defaults to False.

        Returns:
            Response: The HTTP response object.
        """
        try:
            response = self.http_client.send_request(
                url=url,
                method="GET",
                headers=self.args.headers,
                allow_redirects=allow_redirects,
                timeout=self.args.timeout
            )
            return response

        except Exception as e:
            return None