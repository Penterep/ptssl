#!/usr/bin/python3
"""
Copyright (c) 2025 Penterep Security s.r.o.

ptssl is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ptssl is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ptssl.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import importlib
import os
import threading
import subprocess
import shutil
import itertools
import time
import json
import hashlib
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import fcntl
import uuid

from io import StringIO
from types import ModuleType
from urllib.parse import urlparse, urlunparse
from contextlib import contextmanager

from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint, print_banner, help_print, get_colored_text
from ptlibs.threads import ptthreads, printlock
from ptlibs.http.http_client import HttpClient

from helpers._thread_local_stdout import ThreadLocalStdout
from helpers.helpers import Helpers
from _version import __version__

import requests

class PtSSL:
    def __init__(self, args):
        self.ptjsonlib   = ptjsonlib.PtJsonLib()
        self.ptthreads   = ptthreads.PtThreads()
        self._lock       = threading.Lock()
        self.args        = args
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)
        self.helpers     = Helpers(args=self.args, ptjsonlib=self.ptjsonlib, http_client=self.http_client)

        self.testssl_result = self._run_testssl(args.url)

        # Activate ThreadLocalStdout stdout proxy
        self.thread_local_stdout = ThreadLocalStdout(sys.stdout)
        self.thread_local_stdout.activate()

    def run(self) -> None:
        """Main method"""
        tests = self.args.tests or _get_all_available_modules()
        self.ptthreads.threads(tests, self.run_single_module, self.args.threads)

        self.ptjsonlib.set_status("finished")
        ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)


    def _run_testssl(self, url) -> None:
        """
        Executes testssl.sh scan against the specified URL and returns parsed JSON results.

        Workflow:
        - Checks if a cached JSON result file exists (based on an MD5 hash of the URL) and is fresh (not older than 30 minutes).
        If a valid cache is found, loads and returns it without re-running testssl.sh.
        - If no valid cache exists, verifies that `testssl` is available in PATH, otherwise aborts with an error.
        - Removes any stale temporary cache file before running testssl.sh to avoid conflicts.
        - Runs testssl.sh with JSON output directed to a temporary cache file.
        - Shows live CLI output as a spinner or verbose output depending on the verbosity setting.
        - On success, reads JSON results from the temporary file, atomically replaces the final cache file,
        and returns the parsed data.
        - On subprocess error, reports via `end_error`.
        - Ensures the cursor is shown again and spinner thread is stopped when done.

        Args:
            url (str): Target hostname or IP address to scan.

        Returns:
            dict: Parsed JSON output from testssl.sh.

        Raises:
            subprocess.CalledProcessError: If the testssl.sh subprocess fails.
        """
        def load_valid_cache(path, max_age_seconds):
            if not os.path.exists(path):
                return None
            try:
                if (time.time() - os.path.getmtime(path)) > max_age_seconds:
                    raise ValueError("Cache expired")
                with open(path, "r") as f:
                    return json.load(f)
            except Exception:
                try:
                    os.remove(path)
                except Exception:
                    pass
                return None

        def spinner_func(stop_event):
            spinner = itertools.cycle(["|", "/", "-", "\\"])
            spinner_dots = itertools.cycle(["."] * 5 + [".."] * 6 + ["..."] * 7)
            if not self.args.json:
                sys.stdout.write("\033[?25l")  # Hide cursor
                sys.stdout.flush()
            while not stop_event.is_set():
                ptprint(get_colored_text(f"[{next(spinner)}] ", "TITLE") + f"Testssl is running, please wait {next(spinner_dots)}", "TEXT", not self.args.json, end="\r", flush=True, clear_to_eol=True, colortext="TITLE")
                time.sleep(0.1)
            ptprint(" ", "TEXT", not self.args.json, flush=True, clear_to_eol=True)

        if not shutil.which("testssl"):
            self.ptjsonlib.end_error("testssl.sh is not installed or not found in PATH. Please install it first via `sudo apt install testssl.sh`.", self.args.json)

        cache_dir = ptmisclib.get_penterep_temp_dir()
        os.makedirs(cache_dir, exist_ok=True)

        hash_name = hashlib.md5(url.encode("utf-8")).hexdigest()
        final_cache_file = os.path.join(cache_dir, f"{hash_name}.json")
        #temp_cache_file = final_cache_file + ".tmp"
        temp_cache_file = os.path.join(cache_dir, f"{hash_name}_{uuid.uuid4().hex}.tmp")
        CACHE_EXPIRY_SECONDS = 30 * 60 # 30 mins

        if self.args.verbose:
            ptprint(f"Testssl is running, please wait:", "TITLE", not self.args.json, flush=True, clear_to_eol=True, colortext=True, end="")
            if not self.args.json:
                sys.stdout.write("\033[?25l")  # Hide cursor

        else:
            stop_spinner = threading.Event()
            spinner_thread = threading.Thread(target=spinner_func, args=(stop_spinner,))
            ptprint(f" ", "TEXT", not self.args.json, end="\n", flush=True, clear_to_eol=True)
            spinner_thread.start()

        try:
            with self.acquire_testssl_lock(url, cache_dir):
                cached_result = load_valid_cache(final_cache_file, CACHE_EXPIRY_SECONDS)
                if cached_result is not None:
                    return cached_result

                if os.path.exists(temp_cache_file):
                    try:
                        os.remove(temp_cache_file)
                    except Exception:
                        pass

                subprocess.run(
                    ["testssl", "--jsonfile", temp_cache_file, "--logfile", "/dev/stdout", url],
                    check=True,
                    bufsize=1,
                    universal_newlines=True,
                    stdout=sys.stdout if self.args.verbose else subprocess.DEVNULL,
                    stderr=sys.stderr if self.args.verbose else subprocess.DEVNULL
                )

                with open(temp_cache_file, "r") as f:
                    result = json.load(f)

                os.replace(temp_cache_file, final_cache_file)

            return result

        except subprocess.CalledProcessError as e:
            self.ptjsonlib.end_error("testssl.sh raised exception:", details=e, condition=self.args.json)

        finally:
            if not self.args.json:
                sys.stdout.write("\033[?25h")  # Show cursor
            if not self.args.verbose:
                stop_spinner.set()
                spinner_thread.join()

    @contextmanager
    def acquire_testssl_lock(self, url: str, cache_dir: str):
        """
        Context manager for exclusive testssl execution per domain.

        If another process is already testing the same URL, this will block
        until the lock is released. Lock is automatically released when the
        context exits or if the process is terminated normally.

        Args:
            url (str): URL/domain to test
            cache_dir (str): directory for cache and lock files
        """
        os.makedirs(cache_dir, exist_ok=True)
        hash_name = hashlib.md5(url.encode("utf-8")).hexdigest()
        lock_file_path = os.path.join(cache_dir, f"{hash_name}.lock")

        with open(lock_file_path, "w") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                yield
            finally:
                # lock automatically released when file is closed
                pass

    def run_single_module(self, module_name: str) -> None:
        """
        Safely loads and executes a specified module's `run()` function.

        The method locates the module file in the "modules" directory, imports it dynamically,
        and executes its `run()` method with provided arguments and a shared `ptjsonlib` object.
        It also redirects stdout/stderr to a thread-local buffer for isolated output capture.

        If the module or its `run()` method is missing, or if an error occurs during execution,
        it logs appropriate messages to the user.

        Args:
            module_name (str): The name of the module (without `.py` extension) to execute.
        """
        try:
            with self._lock:
                module = _import_module_from_path(module_name)

            if hasattr(module, "run") and callable(module.run):
                buffer = StringIO()
                self.thread_local_stdout.set_thread_buffer(buffer)
                try:
                    module.run(
                        args=self.args,
                        ptjsonlib=self.ptjsonlib,
                        helpers=self.helpers,
                        testssl_result=self.testssl_result
                    )

                except Exception as e:
                    ptprint(e, "ERROR", not self.args.json)
                    error = e
                else:
                    error = None
                finally:
                    self.thread_local_stdout.clear_thread_buffer()
                    with self._lock:
                        ptprint(buffer.getvalue(), "TEXT", not self.args.json, end="\n")
            else:
                ptprint(f"Module '{module_name}' does not have 'run' function", "WARNING", not self.args.json)

        except FileNotFoundError as e:
            ptprint(f"Module '{module_name}' not found", "ERROR", not self.args.json)
        except Exception as e:
            ptprint(f"Error running module '{module_name}': {e}", "ERROR", not self.args.json)



def _import_module_from_path(module_name: str) -> ModuleType:
    """
    Dynamically imports a Python module from a given file path.

    This method uses `importlib` to load a module from a specific file location.
    The module is then registered in `sys.modules` under the provided name.

    Args:
        module_name (str): Name under which to register the module.

    Returns:
        ModuleType: The loaded Python module object.

    Raises:
        ImportError: If the module cannot be found or loaded.
    """
    module_path = os.path.join(os.path.dirname(__file__), "modules", f"{module_name}.py")

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None:
        raise ImportError(f"Cannot find spec for {module_name} at {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

def _get_all_available_modules() -> list:
    """
    Returns a list of available Python module names from the 'modules' directory.

    Modules must:
    - Not start with an underscore
    - Have a '.py' extension
    """
    modules_folder = os.path.join(os.path.dirname(__file__), "modules")
    available_modules = [
        f.rsplit(".py", 1)[0]
        for f in sorted(os.listdir(modules_folder))
        if f.endswith(".py") and not f.startswith("_")
    ]
    return available_modules

def get_help():
    """
    Generate structured help content for the CLI tool.

    This function dynamically builds a list of help sections including general
    description, usage, examples, and available options. The list of tests (modules)
    is generated at runtime by scanning the 'modules' directory and reading each module's
    optional '__TESTLABEL__' attribute to describe it.

    Returns:
        list: A list of dictionaries, where each dictionary represents a section of help
              content (e.g., description, usage, options). The 'options' section includes
              available command-line flags and dynamically discovered test modules.
    """

    # Build dynamic help from available modules
    def _get_available_modules_help() -> list:
        rows = []
        available_modules = _get_all_available_modules()
        modules_folder = os.path.join(os.path.dirname(__file__), "modules")
        for module in available_modules:
            mod = _import_module_from_path(module)
            label = getattr(mod, "__TESTLABEL__", f"Test for {module.upper()}")
            row = ["", "", f" {module.upper()}", label.rstrip(':')]
            rows.append(row)
        return sorted(rows, key=lambda x: x[2])

    return [
        {"description": ["Penterep template script"]},
        {"usage": ["ptssl <options>"]},
        {"usage_example": [
            "ptssl -u https://www.example.com",
        ]},
        {"options": [
            ["-u",  "--url",                    "<url>",            "Connect to URL"],
            ["-ts", "--tests",                  "<test>",     "Specify one or more tests to perform:"],
            *_get_available_modules_help(),
            ["", "", "", ""],
            ["-t",  "--threads",                "<threads>",        "Set thread count (default 10)"],
            ["-vv", "--verbose",                "",                 "Show verbose output"],
            ["-v",  "--version",                "",                 "Show script version and exit"],
            ["-h",  "--help",                   "",                 "Show this help message and exit"],
            ["-j",  "--json",                   "",                 "Output in JSON format"],
        ]
        }]

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help="False", description=f"{SCRIPTNAME} <options>")
    parser.add_argument("-u",  "--url",            type=str, required=True)
    parser.add_argument("-ts", "--tests",          type=lambda s: s.lower(), nargs="+")
    parser.add_argument("-t",  "--threads",        type=int, default=10)
    parser.add_argument("-vv", "--verbose",        action="store_true")
    parser.add_argument("-j",  "--json",           action="store_true")
    parser.add_argument("-v",  "--version",        action='version', version=f'{SCRIPTNAME} {__version__}')

    parser.add_argument("--socket-address",          type=str, default=None)
    parser.add_argument("--socket-port",             type=str, default=None)
    parser.add_argument("--process-ident",           type=str, default=None)

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprint(help_print(get_help(), SCRIPTNAME, __version__))
        sys.exit(0)

    args = parser.parse_args()

    if not args.url.startswith("https://"):
        ptjsonlib.PtJsonLib().end_error("The provided URL uses plain HTTP, which is not secured by SSL/TLS.",
        details="This tool is designed to test SSL/TLS configurations on HTTPS (SSL-secured) endpoints only.",
        condition=args.json)

    args.url = urlunparse(urlparse(args.url)._replace(path='', params='', query='', fragment=''))

    print_banner(SCRIPTNAME, __version__, args.json, 0)
    return args

def main():
    global SCRIPTNAME
    SCRIPTNAME = os.path.splitext(os.path.basename(__file__))[0]
    args = parse_args()
    script = PtSSL(args)
    script.run()

if __name__ == "__main__":
    main()
