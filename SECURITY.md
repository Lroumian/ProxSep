# Security Policy

## Reporting a vulnerability

Please do not open a public issue for vulnerabilities that could enable traffic interception, privilege escalation, driver abuse, credential exposure, or policy bypass.

Use GitHub's private vulnerability reporting / Security Advisory flow for this repository when available.

If private reporting is unavailable, open a minimal issue that does not include exploit details and ask the maintainer for a private contact channel.

## Scope

Security-sensitive areas include:

- WFP / kernel driver behavior.
- Privileged service IPC.
- Process identity attribution.
- Proxy authentication and stored credentials.
- DNS mapping and route-policy bypass.
- Transparent redirection.
- Configuration parsing where crafted input could cause memory, logic, or privilege issues.

## Driver status

The ProxSep WFP driver is experimental. It is not currently presented as a signed, production-ready kernel component.

Do not disable Windows security features solely to test an untrusted build.
