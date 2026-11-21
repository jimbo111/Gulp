# Security policy

## Reporting a vulnerability in Gulp

Gulp handles intercepted traffic, a local certificate authority and stored credentials, so bugs in
Gulp itself matter. If you find one, please report it privately through GitHub's
[private vulnerability reporting](../../security/advisories/new) rather than in a public issue.

Include what you found, how to reproduce it, and the version or commit you tested. You'll get an
acknowledgement within a week. Once a fix is released, the advisory is published with credit to you
unless you'd rather stay anonymous.

In scope: the proxy, the TLS interception and CA handling, project files and secret storage, the
MCP server and agent tool gate, the extension hosts, and anything that could make Gulp send traffic
outside the configured scope.

Out of scope: findings in VulnLab (`gulp-vulnlab`), which is deliberately vulnerable and binds to
localhost only.

## Using Gulp

Gulp is for authorized security testing. Use it on your own systems, on systems you have written
permission to test, and on labs like VulnLab.
