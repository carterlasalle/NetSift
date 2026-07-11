# Security policy

## Supported versions

The latest release on the default branch receives security fixes.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. Do not open a public issue
for memory exhaustion, parser differentials, unbounded recursion, terminal escape injection, or
captures that expose private traffic. Include the smallest synthetic reproducer, affected version,
expected behavior, and impact. You can expect acknowledgement within seven days.

NetSift performs offline parsing with no runtime dependencies or network access. Treat every capture
as untrusted. Run it as an unprivileged user and review structured output before sharing it.

