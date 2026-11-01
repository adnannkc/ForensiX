# Security Policy

## Offline Design and Network Policy

ForensiX is an offline forensic tool designed for secure digital investigations. It makes no external network calls. The only network socket ForensiX ever opens is for the optional local dashboard service, which binds strictly to the loopback address (`127.0.0.1`).

## Reporting a Security Vulnerability

If you discover a security issue or vulnerability in ForensiX, please report it confidentially:

- Use GitHub's private security advisory feature via the repository's **Security** tab (**Report a vulnerability**).
- Please **do not** open a public issue, discussion, or pull request for security vulnerabilities until they have been reviewed and addressed.

## Scope

### In Scope
- **Evidence handling**: Ensuring evidence files are read strictly in read-only binary mode without tampering, modification, or corruption.
- **Output isolation**: Preventing path traversals, unsafe file operations, or unintended writes outside designated output directories.
- **Loopback check**: Ensuring dashboard binding strictly rejects non-loopback network interfaces.
- **Integrity claims**: Verifying the correctness of cryptographic hashing, custody ledger chains, and manifest validations.

### Out of Scope
- Synthetic example data included in tests and documentation.
- Misuse of the tool on systems or evidence you do not have explicit authorization or legal permission to examine.
