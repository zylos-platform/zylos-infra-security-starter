# Security Policy

## Reporting Vulnerabilities

Report security issues privately via GitHub's "Security advisories" tab on this repository, **not** as a public issue.

We aim to acknowledge reports within 72 hours and provide a fix or mitigation timeline within 7 business days for issues classified as High or Critical.

## Supported Versions

Only the latest released minor version receives security patches. Earlier versions are not supported.

## Scope

This starter is a library; it does not itself accept external traffic. Vulnerabilities in scope:

- Incorrect JWT validation (signature, claims, time bounds)
- Incorrect actor chain validation
- Cache poisoning or improper invalidation
- Inappropriate logging of secrets

Out of scope:

- Vulnerabilities in transitive dependencies (report to upstream)
- Misconfiguration by consuming services
