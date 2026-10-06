# Configuration reference

Configuration is loaded in this order:

    defaults → JSON configuration file → FAS_* environment variables → CLI/application overrides

| Field | Default | Environment variable |
|---|---|---|
| database_url | sqlite:///./.fas/fas.db | FAS_DATABASE_URL |
| object_store_path | .fas/objects | FAS_OBJECT_STORE_PATH |
| tenant_id | local | FAS_TENANT_ID |
| subject_id | local | FAS_SUBJECT_ID |
| role | admin | FAS_ROLE |
| api_host | 127.0.0.1 | FAS_API_HOST |
| api_port | 8765 | FAS_API_PORT |
| api_token | unset | FAS_API_TOKEN |
| auth_required | false | FAS_AUTH_REQUIRED |
| max_workers | 2 | FAS_MAX_WORKERS |
| analysis_timeout_seconds | 900 | FAS_ANALYSIS_TIMEOUT_SECONDS |
| subprocess_timeout_seconds | 120 | FAS_SUBPROCESS_TIMEOUT_SECONDS |
| max_stdout_bytes | 2000000 | FAS_MAX_STDOUT_BYTES |
| max_stderr_bytes | 2000000 | FAS_MAX_STDERR_BYTES |
| max_artifact_bytes | 50000000 | FAS_MAX_ARTIFACT_BYTES |
| max_graph_nodes | 200000 | FAS_MAX_GRAPH_NODES |
| max_graph_edges | 500000 | FAS_MAX_GRAPH_EDGES |
| log_level | INFO | FAS_LOG_LEVEL |
| network_policy | DENY_ALL | FAS_NETWORK_POLICY |
| retention_days | 90 | FAS_RETENTION_DAYS |

Numeric limits must be positive. Roles are reader, analyst, and admin. Network policy is DENY_ALL or ALLOWLIST.

Never commit FAS_API_TOKEN or other secrets.
