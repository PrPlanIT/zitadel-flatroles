# zitadel-flatroles

**FlatRoles** — a tiny Go HTTP target for **Zitadel Actions v2**. Zitadel calls it on
`preuserinfo` / `preaccesstoken`; it returns a flat, de-duplicated `roles` claim built
from every role key across the user's project grants, so downstream applications can map a
user to groups from a simple string array.

<!-- sf:project:start -->
<!-- sf:project:end -->
<!-- sf:badges:start -->
<!-- sf:badges:end -->
<!-- sf:image:start -->
<!-- sf:image:end -->

## Why

Zitadel has no built-in "flatten roles". By default it emits roles as a deeply nested
object keyed by project and grant — e.g.

```json
"urn:zitadel:iam:org:project:roles": { "admin": { "201982826478953724": "zitadel.localhost" } }
```

That structure carries the full grant context, but many consumers can't use it as-is.
Role-based authorization in common OIDC consumers — the Kubernetes API server
(`oidc`/structured-auth group mapping), oauth2-proxy, HashiCorp Vault/OpenBao — expects a
*flat string array* of roles/groups, not a nested map. Zitadel's guidance is to produce
that flat shape with a custom claim via an Action
([Custom Claims in ZITADEL](https://zitadel.com/blog/custom-claims)).

This runs that as a v2 **target** (an external HTTP endpoint this binary serves) rather
than the legacy v1 embedded JS action, so the logic is versioned, tested, and image-pinned
instead of living as pasted JavaScript in the Zitadel console.

### Security note — resource-org vs. external-org actions

Zitadel runs the token-flow Action of the **user's** organization, not the application's.
A flat-roles Action configured in one org does **not** fire for users who authenticate
from a *different* org — and that external org's admins can configure their own Action to
inject arbitrary roles into the token
([zitadel/zitadel#9141](https://github.com/zitadel/zitadel/issues/9141)). Treat the flat
`roles` claim as authoritative **only** for identities from organizations you control; if
you federate external orgs, scope group mapping per-org before trusting the claim.

### Payload integrity — the ZITADEL-Signature header

Zitadel signs every target call: it sends the payload as JSON with a `ZITADEL-Signature`
header carrying an HMAC-SHA256 over `<unix-timestamp>.<body>` (plus the timestamp, so
stale/replayed requests can be rejected), keyed by the per-Target **signing key** returned
when the Target is created. The header is `t=<unix>,v1=<hex>[,v1=<hex>...]` (one `v1` per
active key, so key rotation is seamless), documented under
[Verify Payload Integrity](https://zitadel.com/docs/guides/integrate/actions/testing-request-signature).

This binary verifies that signature **when `SIGNING_KEY` is set** — HMAC computed over the
exact request bytes, a constant-time compare against each `v1`, and a 5-minute freshness
window (matching Zitadel's default tolerance). A request with a missing, malformed, stale,
or non-matching signature is rejected with `401`. The check is a stdlib-only
(`crypto/hmac`) reimplementation of Zitadel's scheme — no SDK dependency, so the image
stays distroless-static — and is covered by tests including a golden vector computed
independently of the Go code.

When `SIGNING_KEY` is **unset** the binary does no caller authentication of its own — it
answers any client that can reach it, so it must sit behind a network control that limits
who may call it. Setting `SIGNING_KEY` to the Target's signing key authenticates the
request itself, in-process and independent of network posture — the only thing standing
between a caller and a forged `roles` claim if that network boundary is ever misconfigured
or absent.

## References

- [Actions v2 (concepts)](https://zitadel.com/docs/concepts/features/actions_v2) — Target +
  Execution model; an external endpoint reacting to Request / Response / Function / Event.
- [Custom Claims in ZITADEL](https://zitadel.com/blog/custom-claims) — why the nested role
  claim is hard to consume and how an Action produces a flat array.
- [Verify Payload Integrity](https://zitadel.com/docs/guides/integrate/actions/testing-request-signature)
  — the `ZITADEL-Signature` HMAC header and how a target validates it.
- [Using Actions](https://zitadel.com/docs/guides/integrate/actions/usage) — creating the
  Target (and retrieving its signing key) and wiring the Execution.
- [zitadel/zitadel#9141](https://github.com/zitadel/zitadel/issues/9141) — resource-org vs.
  external-org Action execution and the role-injection risk.

## Contract

- `GET /healthz` → `ok`
- `POST /` (the Zitadel v2 target) → `{"append_claims":[{"key":"roles","value":[...]}]}`
  (empty `{}` when the user holds no roles)

Caller auth: set `SIGNING_KEY` to verify the `ZITADEL-Signature` HMAC in-process;
otherwise the binary authenticates no caller and must be fronted by a network control. See
[Payload integrity](#payload-integrity--the-zitadel-signature-header).

## Config

| env | default | meaning |
|-----|---------|---------|
| `PORT` | `8080` | listen port |
| `CLAIM_NAME` | `roles` | claim key appended to the token |
| `SIGNING_KEY` | _(unset)_ | Target signing key; when set, the `ZITADEL-Signature` HMAC is verified and bad/stale requests get `401`. Unset = in-process verification off (network control only). |
