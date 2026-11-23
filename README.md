# API Security Assessment Toolkit

Assess synthetic API authorization outcomes against a JSON permission matrix. The CLI runs locally with Python 3.10 or later and uses only the standard library at runtime. It makes no network calls and uses no AI inference.

## Run or install

Run directly from the project directory:

```sh
python3 -m api_security_toolkit --help
```

To install the optional `api-security-assess` command, use an environment that already has pip and setuptools 61 or later. The flags keep the installation offline.

```sh
python3 -m pip --disable-pip-version-check install --no-index --no-deps --no-build-isolation .
api-security-assess --help
```

## Demonstration

```sh
python3 -m api_security_toolkit \
  --evidence fixtures/evidence.json \
  --policy fixtures/policy.json \
  --out-dir reports/demo

python3 -m api_security_toolkit \
  --evidence fixtures/contradictory-evidence.json \
  --policy fixtures/policy.json \
  --out-dir reports/rejected

python3 -m unittest discover -s tests -v
```

The first invocation writes `report.json` and `report.md`, with three confirmed cases and one case in each remaining classification. Both reports include the observation references, matched policy rules, and a reason per case. Exit code 0 means the assessment completed, regardless of classifications. The second invocation returns exit code 2 and identifies the conflicting references before writing any reports. Valid runs replace existing reports in the selected output directory.

## Input format

The files in [fixtures](fixtures/) provide complete version 1 examples. All listed fields are required. IDs, operation names, roles, tenant names, and references begin with an ASCII letter or digit and can also contain periods, underscores, colons, slashes, and hyphens after the first character. They are case-sensitive. Operation IDs should identify a single authorization action, such as `read-record` or `change-settings`. Each input represents a single fixed authorization and resource context.

The evidence document contains integer `schema_version: 1`, boolean `synthetic: true`, and these arrays:

| Array | Record fields |
| --- | --- |
| `actors` | `id`, `role`, `tenant` |
| `resources` | `id`, `tenant`, `owner` (actor ID in that tenant, or JSON `null` for a tenant-level resource) |
| `cases` | `id`, `check`, `operation`, `resource` (resource ID), `subject` (actor ID), `observations` (array) |
| `observations` within each case | `ref` (globally unique evidence reference), `actor` (actor ID), `outcome` |

Use `allowed` only when the synthetic record establishes that the named authenticated actor obtained the protected data or that the protected action took effect. An HTTP success status alone is `inconclusive`. Use `denied` for an observed authorization refusal and `inconclusive` when the outcome is ambiguous or unavailable. Each observation covers the case's exact operation and resource.

The permission document contains integer `schema_version: 1` and a `rules` array. Every rule has a unique `id`, an `operation`, a `role`, a `relation`, and a `decision` of `allow` or `deny`. Lookup uses an exact operation, role, and relation match. An absent rule means the expected decision is unknown.

The toolkit derives the relation from the actor and resource. Different tenants produce `cross_tenant`. Within the same tenant, a tenant-level resource produces `tenant`, an actor-owned resource produces `own`, and a peer-owned resource produces `same_tenant_other`.

## Decision rules

A positive control is a different actor in the same case who successfully performed the same operation on the same resource, with explicit permission and the comparison described below.

| Check | Subject condition | Comparable control |
| --- | --- | --- |
| `idor_bola` | Same tenant, resource owned by another actor | Owner with the subject's role |
| `broken_function_level_authorization` | Tenant-level or peer-owned resource within the subject's tenant | Different role with the same resource relation |
| `cross_tenant_access` | Resource in another tenant | Same role inside the resource tenant, using a tenant-level or peer-owned resource |

| Classification | Required evidence |
| --- | --- |
| `confirmed` | Explicit deny, observed subject success, and a comparable positive control |
| `suspected` | Explicit deny and observed subject success, with no comparable positive control |
| `no_finding` | Explicit allow with observed subject success, or explicit deny with observed subject denial and a comparable positive control |
| `insufficient_evidence` | Any remaining valid case, including missing policy, inconclusive observations, unsupported denials, and an unexpected denial despite explicit permission |

Conflicting policy decisions for the same lookup key and observed success plus observed denial for the same operation, resource, and actor invalidate the whole input. The latter applies across case boundaries. Inconclusive observations can coexist with a decisive outcome.

## Limitations

- Outcomes, actor and resource metadata, and evidence provenance are trusted synthetic assertions. The toolkit cannot independently validate them, and classifications apply only to the supplied cases.
- The matrix models one role and one tenant per actor with exact rules. It has no role inheritance, wildcard rules, time-dependent permissions, or session state.
- Each case covers one declared check and requires a control on the same resource. Cross-tenant cases use an in-tenant non-owner control for owned resources to avoid mixing tenant membership with ownership.
- Reports contain no assessment of unobserved operations, actors, tenants, or resources.
