# Environment variables

Runtime settings use the FAS_ prefix.

Examples:

    FAS_API_PORT=9000 fas api
    FAS_NETWORK_POLICY=DENY_ALL fas analyze ./project --format json

See [Configuration](configuration.md) for the complete list.

Secrets such as FAS_API_TOKEN must be supplied through a protected environment or secret manager and never committed.
