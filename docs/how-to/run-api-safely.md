# Run the local API safely

Start the API locally with <code>fas api</code>. The default bind address is 127.0.0.1:8765.

> [!WARNING]
> Do not expose the API to an untrusted network with local-development authentication disabled.

For externally reachable deployments, configure bearer-token authentication and review [SECURITY.md](../../SECURITY.md) and the [threat model](../threat-model/README.md).

The API is the transport/service boundary. Security reasoning belongs in the application and domain layers.
