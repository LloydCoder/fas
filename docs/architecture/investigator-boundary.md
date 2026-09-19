# Investigator Boundary

The investigator model is an untrusted reasoning component. Trusted components are domain validation, immutable snapshot scope, graph/evidence access, tool authorization, budgets and structured output validation.

Repository source, SARIF, tool output, dependency metadata and MCP descriptions are untrusted data. The model never receives database credentials, arbitrary filesystem handles, shell access, network access, or graph mutation privileges. Authorization is enforced outside the model.
