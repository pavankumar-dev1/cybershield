# Detection Limitations

CyberShield uses small, transparent rule sets to demonstrate cybersecurity concepts. It does not connect to external breach databases, URL reputation services, wireless scanners, or mobile-device permission managers.

## Digital footprint checker

The checker searches the supplied text for a fixed list of words such as `breach`, `dump`, and `exposed`. A match is not evidence that personal data was leaked. A lack of matches does not mean that an account has never been breached.

## Password analyzer

The score counts length and character categories. It does not estimate guessability using a password-cracking model, check known compromised passwords, or account for common patterns and reused credentials. Do not enter a real password into a public or untrusted deployment.

## Phishing URL detector

The detector checks a few string patterns, including HTTP, suspicious words, IP-address hosts, selected top-level domains, and subdomain count. It does not resolve DNS, inspect certificates, follow redirects, or query threat-intelligence feeds. Attackers can use legitimate-looking domains, and benign URLs can contain suspicious words.

## App permission analyzer

Permission labels are matched against a static list. The result does not inspect an installed application, its manifest, runtime behavior, Android version, or permission protection level. Permissions can be legitimate depending on an app's purpose.

## Wi-Fi risk indicator

The result is based only on the supplied encryption label and public/private flag. It does not inspect the actual access point, router configuration, client isolation, captive portal, or traffic.

## Safe interpretation

Treat every result as a learning aid and a prompt for further verification. A SAFE status is not a security certification.
