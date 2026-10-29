# zitadel-flatroles

**FlatRoles** — a tiny Go HTTP target for **Zitadel Actions v2**. Zitadel calls it on
`preuserinfo` / `preaccesstoken`; it returns a flat, de-duplicated `roles` claim built
from every role key in the grants Zitadel sends with the call, so downstream applications
can map a user to groups from a simple string array.

<!-- sf:project:start -->
[![GitHub](https://img.shields.io/badge/GitHub-mirror-181717?logo=github)](https://github.com/PrPlanIT/zitadel-flatroles) [![GitLab](https://img.shields.io/badge/GitLab-source-FC6D26?logo=gitlab)](https://gitlab.prplanit.com/PrPlanIT/zitadel-flatroles) [![license](https://raw.githubusercontent.com/PrPlanIT/zitadel-flatroles/main/.stagefreight/scribe/license.svg)](https://github.com/PrPlanIT/zitadel-flatroles/blob/main/LICENSE) [![Open Issues](https://img.shields.io/github/issues/PrPlanIT/zitadel-flatroles)](https://github.com/PrPlanIT/zitadel-flatroles/issues) [![Open PRs](https://img.shields.io/github/issues-pr/PrPlanIT/zitadel-flatroles)](https://github.com/PrPlanIT/zitadel-flatroles/pulls) [![Contributors](https://img.shields.io/github/contributors/PrPlanIT/zitadel-flatroles)](https://github.com/PrPlanIT/zitadel-flatroles/graphs/contributors) [![donate](https://img.shields.io/badge/donate-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/T6T41IT163) [![sponsor](https://img.shields.io/badge/sponsor-EA4AAA?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/PrPlanIT)
<!-- sf:project:end -->
<!-- sf:badges:start -->
[![release](https://raw.githubusercontent.com/PrPlanIT/zitadel-flatroles/main/.stagefreight/scribe/release.svg)](https://github.com/PrPlanIT/zitadel-flatroles/releases) [![build](https://raw.githubusercontent.com/PrPlanIT/zitadel-flatroles/main/.stagefreight/scribe/build.svg)](https://gitlab.prplanit.com/PrPlanIT/zitadel-flatroles/-/pipelines) [![Go Version](https://img.shields.io/github/go-mod/go-version/PrPlanIT/zitadel-flatroles?logo=go)](https://github.com/PrPlanIT/zitadel-flatroles) [![Go Reference](https://pkg.go.dev/badge/github.com/PrPlanIT/zitadel-flatroles.svg)](https://pkg.go.dev/github.com/PrPlanIT/zitadel-flatroles) [![Last Commit](https://img.shields.io/github/last-commit/PrPlanIT/zitadel-flatroles)](https://github.com/PrPlanIT/zitadel-flatroles/commits) [![StageFreight](https://img.shields.io/badge/StageFreight-0.14.0--dev+6c197b0-310937?logo=readthedocs&logoColor=white)](https://stagefreight.prplanit.com)
<!-- sf:badges:end -->
<!-- sf:image:start -->
[![GHCR](https://img.shields.io/badge/GHCR-prplanit%2Fzitadel--flatroles-181717?logo=github&logoColor=white)](https://github.com/PrPlanIT/zitadel-flatroles/pkgs/container/zitadel-flatroles) [![Docker](https://img.shields.io/badge/Docker-prplanit%2Fzitadel--flatroles-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/prplanit/zitadel-flatroles) [![pulls](https://img.shields.io/docker/pulls/prplanit/zitadel-flatroles?color=1d63ed&logo=docker&logoColor=white)](https://hub.docker.com/r/prplanit/zitadel-flatroles) [![Harbor](https://img.shields.io/badge/Harbor-prplanit%2Fzitadel--flatroles-60b932)](https://cr.pcfae.com/harbor/projects)

[![latest](https://raw.githubusercontent.com/PrPlanIT/zitadel-flatroles/main/.stagefreight/scribe/release-latest.svg)](https://github.com/PrPlanIT/zitadel-flatroles/pkgs/container/zitadel-flatroles) ![updated](https://raw.githubusercontent.com/PrPlanIT/zitadel-flatroles/main/.stagefreight/scribe/release-updated.svg) [![size](https://raw.githubusercontent.com/PrPlanIT/zitadel-flatroles/main/.stagefreight/scribe/release-size.svg)](https://github.com/PrPlanIT/zitadel-flatroles/pkgs/container/zitadel-flatroles) [![latest-dev](https://raw.githubusercontent.com/PrPlanIT/zitadel-flatroles/main/.stagefreight/scribe/dev-latest.svg)](https://github.com/PrPlanIT/zitadel-flatroles/pkgs/container/zitadel-flatroles) ![updated](https://raw.githubusercontent.com/PrPlanIT/zitadel-flatroles/main/.stagefreight/scribe/dev-updated.svg) [![size](https://raw.githubusercontent.com/PrPlanIT/zitadel-flatroles/main/.stagefreight/scribe/dev-size.svg)](https://github.com/PrPlanIT/zitadel-flatroles/pkgs/container/zitadel-flatroles)
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

### Which grants arrive — Zitadel scopes them per application

The binary does no filtering of its own: Zitadel has already chosen the grants. The
payload's `user_grants` holds only the user's **active** grants on the projects in the
token's **role audience** (`state = 1` and `project_id = any(<role audience>)` in
Zitadel's `userinfo_by_id.sql`). The role audience is built in `prepareRoles`
(`internal/api/oidc/userinfo.go`):

- the requesting application's own project, whenever roles are asserted for the request
  (always on the userinfo endpoint; for tokens when the project asserts roles, or the client
  requests project roles or other project audiences), and
- every project the client asks for with the
  `urn:zitadel:iam:org:project:id:{projectId}:aud` scope.

A `urn:zitadel:iam:org:id:{orgId}` scope further limits the grants to that organization.

So the flat array is already per application: a key means the role on the app's own
project, or on a project the app explicitly requested — never a grant the user holds on an
unrelated project. The same small set of keys (`operator`, `admin`, `user`, …) can be
reused in every project without prefixes.

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
- [Claims](https://zitadel.com/docs/apis/openidoauth/claims) and
  [Scopes](https://zitadel.com/docs/apis/openidoauth/scopes) — the role claims and the
  `urn:zitadel:iam:org:project:id:{projectId}:aud` / `urn:zitadel:iam:org:id:{orgId}` scopes
  that shape the role audience.
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
