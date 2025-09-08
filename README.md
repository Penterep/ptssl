[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


## PTSSL - Wrapper for testssl.sh


## Installation

```
pip install ptssl
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples
```
ptssl -u htttps://www.example.com/
```

## Options
```
-u   --url      <url>      Connect to URL
-ts  --tests    <test>     Specify one or more tests to perform:
                 CT        Testing for supported ciphers
                 PCT       Testing who gives order of ciphers
                 PT        Testing for allowed protocols
                 TSD       Testing server defaults

-t   --threads  <threads>  Set thread count (default 10)
-vv  --verbose             Show verbose output
-v   --version             Show script version and exit
-h   --help                Show this help message and exit
-j   --json                Output in JSON format
```

## Dependencies
```
ptlibs
```

## External tools
This tool requires [testssl.sh](https://testssl.sh) to be installed and available in your PATH.

We would like to thank the author for their work on this excellent tool.


## License

Copyright (c) 2025 Penterep Security s.r.o.

ptssl is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptssl is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptssl. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!