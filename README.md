# zitadel-flatroles

**FlatRoles** — a tiny Go HTTP target for **Zitadel Actions v2**. Zitadel calls it on
`preuserinfo` / `preaccesstoken`; it returns a flat, de-duplicated `roles` claim built
from every role key across the user's project grants. That claim is load-bearing for
cluster auth — the kube-apiserver maps it to `zitadel:`-prefixed groups.

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

That structure carries the full grant context, but almost nothing downstream can consume
it as-is. Role-based authorization in the tools we run — the **kube-apiserver**
(`oidc`/structured-auth group mapping), **oauth2-proxy**, **HashiCorp Vault/OpenBao** —
all expect a *flat string array* of roles/groups, not a nested map. Zitadel's own guidance
is to produce that flat shape with a custom claim via an Action
([Custom Claims in ZITADEL](https://zitadel.com/blog/custom-claims)).

So this is not a nicety — it is **load-bearing for how every app in the cluster maps a
logged-in user to its authorization groups**. Without the flat claim, the apiserver can't
turn a Zitadel identity into `zitadel:`-prefixed groups, and RBAC falls through to
unauthenticated. We run it the Actions-**v2** way (an external HTTP target this binary
serves) rather than the legacy v1 embedded JS action, so the logic is versioned, tested,
and image-pinned like the rest of the fleet instead of living as pasted JavaScript in the
Zitadel console.

### Security note — resource-org vs. external-org actions

Zitadel runs the token-flow Action of the **user's** organization, not the application's.
That means a flat-roles Action configured in our org does **not** fire for users who
authenticate from a *different* Zitadel org — and, worse, that external org's admins can
configure their own Action to inject arbitrary roles into the token
([zitadel/zitadel#9141](https://github.com/zitadel/zitadel/issues/9141)). Downstream RBAC
must therefore treat the flat `roles` claim as authoritative **only** for identities from
orgs we control. In the dungeon cluster that holds today (single trusted issuer org); if we
ever federate external orgs, group mapping has to be scoped per-org before trusting this
claim.

### Payload integrity — mesh authz vs. the ZITADEL-Signature header

Zitadel signs every target call: it sends the payload as JSON with a `ZITADEL-Signature`
header carrying an HMAC-SHA256 over `<unix-timestamp>.<body>` (plus the timestamp, so
stale/replayed requests can be rejected), keyed by the per-Target **signing key** it hands
you when the Target is created. The header is `t=<unix>,v1=<hex>[,v1=<hex>...]` (one `v1`
per active key, so key rotation is seamless), and Zitadel documents it under
[Verify Payload Integrity](https://zitadel.com/docs/guides/integrate/actions/testing-request-signature).

This binary verifies that signature **when `SIGNING_KEY` is set** — HMAC computed over the
exact request bytes, a constant-time compare against each `v1`, and a 5-minute freshness
window (matching Zitadel's default tolerance). A request with a missing, malformed, stale,
or non-matching signature is rejected with `401`. The check is a stdlib-only
(`crypto/hmac`) reimplementation of Zitadel's scheme — no SDK dependency, so the image
stays distroless-static — and is covered by tests including a golden vector computed
independently of the Go code.

When `SIGNING_KEY` is **unset**, verification is disabled and the only control is the
network layer: the ambient-mesh `AuthorizationPolicy` admits ingress from `sa/zitadel`
only. That is a valid trust boundary but single-layer; set `SIGNING_KEY` (sourced from the
Target's signing key, via Vault/ESO) to get defense-in-depth.

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

Caller auth: the ambient-mesh AuthorizationPolicy restricts ingress to `sa/zitadel`, and —
when `SIGNING_KEY` is set — the `ZITADEL-Signature` HMAC is verified in-process. See
[Payload integrity](#payload-integrity--mesh-authz-vs-the-zitadel-signature-header).

## Config

| env | default | meaning |
|-----|---------|---------|
| `PORT` | `8080` | listen port |
| `CLAIM_NAME` | `roles` | claim key appended to the token |
| `SIGNING_KEY` | _(unset)_ | Target signing key; when set, the `ZITADEL-Signature` HMAC is verified and bad/stale requests get `401`. Unset = verification off (mesh authz only). |
