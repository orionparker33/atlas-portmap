# Security policy

atlas-portmap handles SNMP credentials and serves a local web GUI, so security reports are welcome.

**Report a vulnerability privately** through GitHub's private vulnerability reporting (the
repository's Security tab, "Report a vulnerability"), not in a public issue. Include the version
(`atlas-portmap version`), the operating system and the steps to reproduce.

Supported: the latest release, release candidates included. Fixes are best effort; there is no
response-time commitment.

In scope: the GUI's local-only guard (token, Host, Origin and CSP checks), credential handling
(command line, environment, memory), terminal and CSV output escaping, and anything that lets SNMP
data from a device affect the machine running the tool.

Out of scope: running the GUI with `-allow-remote`, which is documented as plain HTTP for trusted
networks only, and the SNMP protocol's own weaknesses (SNMPv1/v2c communities travel in clear text;
use SNMPv3 with authPriv).
