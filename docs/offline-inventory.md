# API Security Toolkit V0.2 — offline inventory

Python 3.10+ standard-library module integrated into the toolkit package. It reads
local evidence only; it performs no scanning, DNS resolution or deployment.
The existing authorization assessment command remains available independently.

## Run

```sh
python -m api_security_toolkit.inventory --allowlist fixtures/inventory/allowlist.json \
  --subfinder fixtures/inventory/subfinder.jsonl --dnsx fixtures/inventory/dnsx.json \
  --httpx fixtures/inventory/httpx.jsonl --output reports/inventory
python -m unittest discover -s tests -v
```

Each input flag can repeat. Inputs accept JSONL objects, a single object on one
line, or a JSON array. Output must be a new directory; existing reports are never
overwritten. Both reports are staged before either final file is published. An
exclusive `.inventory-incomplete` directory remains until both final files and
staging cleanup succeed. If it exists, the directory is incomplete even when both
report files exist. Consumers must check this marker and CLI exit status; file
presence alone is not completion. Failed/interrupted runs require a fresh output
directory. This is not a crash-durable transaction or a concurrent-reader snapshot.
Exit 0 means all records accepted; 1 means reports include quarantined
records; 2 means invalid files, allowlist, arguments, or IO. Malformed JSON aborts
before report creation. Malformed recognized record fields quarantine the entire
record. Reports contain sensitive inventory data; store them accordingly.

## Authorization contract

The operator must supply a documented authorization allowlist with exactly these
three arrays; empty arrays deny everything of that type:

- `domains`: exact ASCII DNS names or `*.example.test`. Wildcards include any
  descendant, never the apex or suffix lookalikes. Names lowercase and lose one
  terminal dot. Punycode ASCII names are accepted; Unicode names are rejected.
- `networks`: explicit strict IPv4/IPv6 CIDRs (use /32 or /128 for one address).
  Authorized DNS names do not authorize their IP addresses or CNAME targets.
- `endpoints`: exact HTTP(S) URLs. A URL requires both its exact endpoint rule and
  an authorized domain/IP host. Scheme/host case, default ports, empty path and
  IP spelling normalize. Path, percent escapes and query remain exact; there are
  no path-prefix rules. A trailing `?` is preserved and differs from no query
delimiter. Credentials, fragments (including a bare trailing `#`), controls and
backslashes reject.

Every recognized asset in a record must pass. Otherwise the whole record is
quarantined, preventing partially trusted associations. A redirect never extends
scope. Relative redirect locations are conservatively quarantined. An allowlist
is supplied authorization evidence, not proof of permission to collect new data.
The fixture allowlist is synthetic, not authorization to contact anything.

## Supported evidence fields

| Source | Required | Additional asset fields |
| --- | --- | --- |
| Subfinder | `host` DNS/IP string | common fields below |
| dnsx | `host` DNS/IP string | common fields below |
| httpx | absolute `url` | `host`, `host_ip`, absolute `final_url`, absolute `location` |

Common fields: `a` and `aaaa` are arrays of IP strings; `cname`, `ns`, `ptr`, `mx`
are arrays of host strings. Missing optional fields are allowed. Present URL fields must be nonempty absolute
HTTP(S) strings; null, booleans, numbers, arrays and objects quarantine the record. Unknown fields
are ignored metadata and never imported as assets or authorization. This is an
explicit supported subset, not an exhaustive importer for every tool version.
Exporters with other asset-bearing fields need an explicit adapter before those
fields can enter inventory. Status codes, page content, technology tags and
nested redirect chains are not imported. No live tool execution is needed.

## Determinism and evidence

Domain and subdomain names share the `domain` kind: a subdomain is simply a DNS
name; no public-suffix or inferred ownership lookup is performed. IPs and endpoints
have separate kinds. Assets deduplicate by normalized kind/value. References
identify tool, SHA-256 of the original evidence bytes, and one-based JSON record
ordinal (nonblank JSONL record, not physical line). Keep original input files for
lookup; paths are deliberately excluded so relocation cannot change reports.
Repeated inputs deduplicate references and quarantine entries. Reports sort assets,
sources and references and contain no timestamp. Reordering files produces identical
reports; changing file bytes or record order intentionally changes provenance.
JSON includes all quarantine details; Markdown includes assets, references and
quarantine details with HTML/table escaping.

## Review gate

Branch: `feature/ori-17-v0.2-reviewed-main`. No push, deployment or merge is part
of this delivery. Human approval is required before any merge. The review bundle
contains source, fixtures, tests and generated sample reports. Tests cover denied
scope, wildcard bypasses, redirect/IP scope inheritance, malformed records and
allowlists, canonicalization, provenance, deterministic output and CLI behavior.
