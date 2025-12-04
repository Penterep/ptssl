DESCRIPTION_MAP = {
    "heartbleed": {
        "name": "Heartbleed Vulnerability",
        "description": "Indicates whether the server is vulnerable to the Heartbleed bug in OpenSSL."
    },
    "CCS": {
        "name": "CCS Injection Vulnerability",
        "description": "Checks if the server is vulnerable to ChangeCipherSpec injection attacks."
    },
    "ticketbleed": {
        "name": "Ticketbleed Vulnerability",
        "description": "Indicates vulnerability to Ticketbleed attacks against TLS session tickets."
    },
    "ROBOT": {
        "name": "ROBOT Attack",
        "description": "Checks if the server is vulnerable to RSA padding oracle attacks."
    },
    "secure_renego": {
        "name": "Secure TLS Renegotiation",
        "description": "Indicates if secure renegotiation is supported."
    },
    "secure_client_renego": {
        "name": "Secure Client Renegotiation",
        "description": "Indicates if secure client-initiated renegotiation is supported."
    },
    "CRIME_TLS": {
        "name": "CRIME Vulnerability",
        "description": "Checks for vulnerability to the CRIME attack on TLS compression."
    },
    "BREACH": {
        "name": "BREACH Vulnerability",
        "description": "Indicates vulnerability to BREACH attacks on HTTP compression."
    },
    "POODLE_SSL": {
        "name": "POODLE SSL Vulnerability",
        "description": "Checks if server is vulnerable to the POODLE attack on SSL 3.0."
    },
    "fallback_SCSV": {
        "name": "TLS Fallback Protection",
        "description": "Indicates if protection against protocol downgrade attacks is supported."
    },
    "SWEET32": {
        "name": "SWEET32 Vulnerability",
        "description": "Checks for vulnerability due to 64-bit block ciphers like 3DES."
    },
    "FREAK": {
        "name": "FREAK Attack",
        "description": "Indicates vulnerability to FREAK attacks using weak export-grade RSA keys."
    },
    "DROWN": {
        "name": "DROWN Attack",
        "description": "Checks for vulnerability to DROWN attacks exploiting SSLv2."
    },
    "LOGJAM": {
        "name": "LOGJAM Attack",
        "description": "Checks for weak Diffie-Hellman parameters susceptible to LOGJAM attacks."
    },
    "BEAST_CBC_TLS1": {
        "name": "BEAST CBC TLS1 Vulnerability",
        "description": "Indicates vulnerability to the BEAST attack on CBC cipher suites in TLS 1.0."
    },
    "BEAST": {
        "name": "BEAST Attack",
        "description": "General check for BEAST attack on TLS 1.0 CBC ciphers."
    },
    "LUCKY13": {
        "name": "LUCKY13 Attack",
        "description": "Checks for timing attack vulnerabilities on CBC padding."
    },
    "winshock": {
        "name": "WinShock / MS14-068 Vulnerability",
        "description": "Checks for vulnerability to the Windows-specific WinShock exploit."
    },
    "RC4": {
        "name": "RC4 Cipher Usage",
        "description": "Indicates whether RC4 cipher is used (not recommended)."
    },
    "cipherlist_NULL": {
        "name": "NULL Cipher List",
        "description": "Checks if ciphers with no encryption are offered."
    },
    "cipherlist_aNULL": {
        "name": "Anonymous Cipher List",
        "description": "Checks if ciphers with no authentication are offered."
    },
    "cipherlist_EXPORT": {
        "name": "Export Cipher List",
        "description": "Checks if weak export-grade ciphers are offered."
    },
    "cipherlist_LOW": {
        "name": "Low Strength Cipher List",
        "description": "Checks if low-strength ciphers are offered."
    },
    "cipherlist_3DES_IDEA": {
        "name": "3DES/IDEA Cipher List",
        "description": "Indicates if older 3DES or IDEA ciphers are offered."
    },
    "cipherlist_OBSOLETED": {
        "name": "Obsolete Cipher List",
        "description": "Checks if obsolete/insecure ciphers are offered."
    },
    "cipherlist_STRONG_NOFS": {
        "name": "Strong Cipher List (No Forward Secrecy)",
        "description": "Strong ciphers offered without Forward Secrecy."
    },
    "cipherlist_STRONG_FS": {
        "name": "Strong Cipher List with FS",
        "description": "Strong ciphers offered with Forward Secrecy."
    },
    "FS": {
        "name": "Forward Secrecy Support",
        "description": "Indicates whether the server offers Forward Secrecy for session keys."
    },
    "testssl": {
        "name": "GREASE Test",
        "description": "Testssl could not provide GREASE section (non-critical informational warning)."
    },
    "cipher_order": {
        "name": "Server Cipher Order",
        "description": "Indicates whether the server dictates the cipher order (recommended for security)."
    },
    "SSLv2": {
        "name": "SSLv2 Protocol",
        "description": "Indicates whether SSLv2 is offered (deprecated, insecure)."
    },
    "SSLv3": {
        "name": "SSLv3 Protocol",
        "description": "Indicates whether SSLv3 is offered (deprecated, insecure)."
    },
    "TLS1": {
        "name": "TLS 1.0 Protocol",
        "description": "Indicates whether TLS 1.0 is offered (deprecated, weak)."
    },
    "TLS1_1": {
        "name": "TLS 1.1 Protocol",
        "description": "Indicates whether TLS 1.1 is offered (deprecated, weak)."
    },
    "TLS1_2": {
        "name": "TLS 1.2 Protocol",
        "description": "Indicates whether TLS 1.2 is offered (secure)."
    },
    "TLS1_3": {
        "name": "TLS 1.3 Protocol",
        "description": "Indicates whether TLS 1.3 is offered (modern and secure, not supported here)."
    },
    "cert_signatureAlgorithm": {
        "name": "Cert Signature Algorithm",
        "description": "The algorithm used to sign the server certificate."
    },
    "cert_keySize": {
        "name": "Certificate Key Size",
        "description": "Size and type of the server certificate key (e.g., RSA 2048 bits)."
    },
    "cert_chain_of_trust": {
        "name": "Certificate Chain of Trust",
        "description": "Validates that the server certificate chain is trusted."
    },
    "cert_trust": {
        "name": "Certificate Trust",
        "description": "Indicates if the certificate is trusted by browsers (SAN and SNI checked)."
    },
    "cert_notAfter": {
        "name": "Certificate Expiration Date",
        "description": "The expiration date of the server certificate."
    },
    "cert_extlifeSpan": {
        "name": "Extended LifeSpan",
        "description": "Indicates whether the certificate has extended lifetime beyond standard recommendations."
    },
    "OCSP_stapling": {
        "name": "OCSP Stapling",
        "description": "Indicates whether OCSP stapling is supported for certificate revocation checking."
    },
    "certificate_transparency": {
        "name": "Certificate Transparency",
        "description": "Indicates if the certificate includes transparency extension to prevent fake certs."
    },
    "HTTP redirect to HTTPS": {
        "name": "HTTP Redirect to HTTPS",
        "description": "Checks if HTTP requests are automatically redirected to HTTPS."
    },
    "HSTS offered": {
        "name": "HSTS Support",
        "description": "Indicates whether the server sends HSTS header to enforce HTTPS."
    },
    "max-age value offered": {
        "name": "HSTS Max-Age",
        "description": "The max-age value sent in HSTS header (time browsers remember to use HTTPS)."
    },
    "preload offered": {
        "name": "HSTS Preload Support",
        "description": "Indicates if the server is ready for inclusion in browser HSTS preload lists."
    },
    "includeSubdomains offered": {
        "name": "HSTS Include Subdomains",
        "description": "Indicates if HSTS applies to all subdomains as well."
    }
}
