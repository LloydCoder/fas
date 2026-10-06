# Governance

FAS is currently maintained under a maintainer-led model.

## Maintainer

The repository maintainer is **@LloydCoder**.

The maintainer is responsible for repository administration, security policy and vulnerability response, release approval, security-sensitive architectural decisions, CODEOWNERS policy, and changes to evidence, verification, execution, and authority boundaries.

## Contributions

Contributors propose changes through issues and pull requests. CODEOWNERS identifies paths requiring maintainer review.

## Security decisions

Security-sensitive changes should include regression coverage and, when appropriate, an ADR and threat-model update. Vulnerabilities must follow [SECURITY.md](SECURITY.md).

## Releases

A release should align:

    version metadata → changelog → Git tag → GitHub Release → package artifacts → SBOM/attestations

The release workflow generates release evidence; maintainers decide when a version is ready to publish.

## Future evolution

If FAS develops a broader maintainer team, this document should define maintainer membership, decision rights, succession, release authority, and dispute resolution.
