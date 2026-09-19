# Release Engineering

FAS uses a single package version in pyproject.toml. The Phase 6 package is currently 0.6.0.

Required release artifacts are a source distribution and wheel, a clean installation check, release notes in CHANGELOG.md, and a Git tag when a release is actually published.

GitHub Actions validates lint, tests, schema parity, package build, clean wheel installation, CLI smoke, and product integration smoke across Python 3.11–3.14.

Third-party GitHub Actions are pinned to full commit SHAs and workflow permissions are explicitly restricted to read-only repository contents. GitHub documents full-SHA pinning and least-privilege token permissions as supply-chain hardening practices.
