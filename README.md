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

Zitadel has no built-in "flatten roles" — the native roles claim is nested per
project/org. This target produces the flat array the apiserver expects, the Actions-v2
way (an external target), replacing the legacy v1 embedded JS action.

## Contract

- `GET /healthz` → `ok`
- `POST /` (the Zitadel v2 target) → `{"append_claims":[{"key":"roles","value":[...]}]}`
  (empty `{}` when the user holds no roles)

Caller auth is the ambient-mesh AuthorizationPolicy (ingress restricted to
`sa/zitadel`); the v2 payload signing-key is not verified.

## Config

| env | default | meaning |
|-----|---------|---------|
| `PORT` | `8080` | listen port |
| `CLAIM_NAME` | `roles` | claim key appended to the token |

Deployed in the dungeon cluster at `fluxcd/infrastructure/services/base/zitadel/flatroles.yaml`.
