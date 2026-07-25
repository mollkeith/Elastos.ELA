# Release manifest — Elastos.ELA v1.0.0

This is the checklist a v1.0.0 release must satisfy. **Every field is marked
`FILLED` or `OPEN`.** A field is `FILLED` only if the value in it was
**measured**, on this tree, with the pinned toolchain — never inferred, never
copied from a previous release. `OPEN` fields must be filled (or explicitly
waived by the owner) before the tag is published.

**Measurement state of this document:** all `FILLED` values were measured on
this tree, offline, with the pinned toolchain. Commit hashes **will change**
when these patches are applied to the canonical tree via `git format-patch` /
`git am` (that rewrites committer metadata), so [§1](#1-identity) must be
re-recorded after merge. The binary digests in [§5](#5-binaries) were verified
to survive that merge — reapplying both patches to a fresh canonical clone and
rebuilding reproduced them exactly — but they must still be **re-measured
before tagging**, because any further source change invalidates them. The
procedure is in [§10](#10-re-measurement-procedure).

---

## 1. Identity

| Field | Status | Value |
|---|---|---|
| Product | `FILLED` | Elastos.ELA main-chain node |
| Version string | `FILLED` | `v1.0.0` |
| Authoritative version constant | `FILLED` | `utils/version/version.go`, `const Version` — the single source of truth for `ela`, `ela-cli` and `ela-dns` |
| Previous **released** version | `FILLED` | `v0.9.9.6`. `v0.9.9.7` was never released. |
| Root snapshot commit | `FILLED` | `d8488bfc7ce46abbe245bf6fe65445a183691840` — *"ELA v0.9.9.7 + all our fixes + battle/exploit tests (2026-07-22)"*. **Verified to be a root commit: it has no parent** (`git log --format='%H %P' -1 d8488bf` prints an empty parent field; `git rev-list --max-parents=0 HEAD` returns exactly this commit). |
| Commit range in this release | `FILLED` | `d8488bf..HEAD` — **108 commits** (`git rev-list --count`), all named in `CHANGELOG.md` (coverage checked mechanically: 0 missing) |
| Canonical base commit | `FILLED` | `21098e0aa3c5b5038a6be2cce3b433481f396833` — the release-meta work sits directly on top of it |
| Code-bearing commit (pre-merge, provisional) | `OPEN` | `273469df9ae98862959bd1281babf7aa5316bcc1`, tree `cab531680ce3df6918ff6cb41736479fdcf761e1`. **This is the state the binaries in [§5](#5-binaries) were built from.** The commit hash **will change on merge** (`git am` rewrites committer metadata); the *tree* hash is content-addressed and will not, as long as no other source change lands. |
| Release tip commit / tree hash | `OPEN` | Self-referential: recording the tip tree hash inside a file that is part of that tree changes it. Record it **after** the final commit, from `git rev-parse HEAD` and `git rev-parse HEAD^{tree}`, and keep it outside the tree (in the signed tag message or the checksum file). |
| Documentation commits do not affect the binaries | `FILLED` | Verified: applying **both** release-meta patches to a fresh canonical clone and running `make release` reproduced the [§5](#5-binaries) sha256 digests **exactly**. |
| Release tag name | `OPEN` | proposed `v1.0.0` |
| Release tag object (signed?) | `OPEN` | GPG key id and signature — not created |
| Final source commit | `OPEN` | fill after merge |
| Final source tree hash | `OPEN` | fill after merge |

---

## 2. Consensus activation — the two height gates

**There are exactly two activation gates in this release. A third is never
permitted.** Verified by inspection of `common/config/config.go` and by the
absence of any new height literal in the release-meta diff.

| Field | Status | Value |
|---|---|---|
| Gate 1 — `MainNetStrictMoneyRangeHeight` | `FILLED` | **2 260 451** (`common/config/config.go`). Inherited unchanged from the root snapshot `d8488bf`. Equals `ForcedRollbackHeight + 1`, i.e. it arms on the first block of the restarted chain. |
| Gate 2 — `MainNetRevisedDPoSRewardHeight` | `FILLED` | **2 265 000** (`common/config/config.go`). **New in v1.0.0**: the constant was added by `e646a5d` as a `MaxUint32` placeholder and given this value by `80378ab`. ~4 405 blocks past the frozen tip 2 260 595 (~6 days at 120 s). |
| Gate 2 — core-engineer confirmation | **`OPEN`** | `80378ab` states this single coordinated value **must be confirmed or adjusted by the core engineers before deploy** and must be byte-identical fleet-wide. Not obtained. |
| Gate 2 production users | `FILLED` | Exactly three: `blockchain/blockvalidator.go` (F-011/086 ELA-only arbiter reward basis) and the V2 and V3 arms of `dpos/state/arbitrators.go` (F-212 empty-slot reward). The fourth user, F-032's block-validity binding, was **withdrawn** in `f6ea5b2`. |
| `MainNetForcedRollbackHeight` | `FILLED` | **2 260 450** — the chain is rewound *to* this height |
| `MainNetForcedRollbackTrigger` | `FILLED` | `e1a11e04942a7513f0256dbf3605080490800fd845f8e261deffcec68c2ea9af` (the block at `ForcedRollbackHeight + 1`) |
| `MainNetCrossChainUTXOFreezeHeight` | `FILLED` | **2 256 110** (inherited from `d8488bf`) |
| `MainNetCrossChainUTXORestrictionHeight` | `FILLED` | **2 256 724** (inherited from `d8488bf`) |
| Third gate present? | `FILLED` | **No.** No height literal was added to `common/config/` by the release-meta change; `git diff -- common/config/ core/ dpos/ cr/ mempool/ blockchain/` for that change is empty. |
| Retained-history invariant | `FILLED` | Retained history **at or below 2 260 450 is unaffected**. Every acceptance-changing rule is a no-op below its gate; every ungated change is crash-hardening, reorg/rollback-only, node-local retention, transport, tooling or configuration. Per-fix evidence (censuses over the full 2 260 597-block retained chain, fail-on-pristine tests, mutation batteries) is recorded in the individual commit messages and summarised in `CHANGELOG.md`. |
| Independent re-derivation of the retained chain on the release binary | **`OPEN`** | A full replay of 0..2 260 450 on the shipped `ela` binary, compared against the frozen store, is **not** recorded here. |

---

## 3. Go toolchain attestation

| Field | Status | Value |
|---|---|---|
| Toolchain version | `FILLED` | `go version go1.20.14 linux/amd64` |
| `GOVERSION` | `FILLED` | `go1.20.14` |
| Toolchain location (pinned) | `FILLED` | `/usr/local/go1.20.14` (`GOROOT`) |
| `sha256(GOROOT/bin/go)` | `FILLED` | `6910d481204033d70e35f488bede9893c737cc88516f958064ea47e4e6045b6d` |
| Toolchain pin file | `FILLED` | `.go-version` = `1.20.14`; asserted by `test/unit.TestF210BuildDeterminismPins` (must be an exact `x.y.z` pin and must match the `go.mod` language version) |
| Toolchain switching disabled | `FILLED` | `GOTOOLCHAIN=local` on every build and test invocation |
| Network access during build | `FILLED` | `GOPROXY=off`. **No fetch of any kind was performed.** All builds resolved from the on-box module cache. |
| `GOOS` / `GOARCH` | `FILLED` | `linux` / `amd64` (pinned by the `release` target) |
| `GOAMD64` | `FILLED` | `v1` (pinned in the Makefile — F-210: float contraction is architecture-dependent, so the microarchitecture level must not be inherited from the builder) |
| `CGO_ENABLED` | `FILLED` | `0` (so the toolchain, not the builder's libc, decides the output) |
| Path trimming | `FILLED` | `-trimpath` (so the builder's directory layout does not leak into the binary) |
| Link-time version stamping | `FILLED` | **None for the release build.** Only `-X 'main.GoVersion=go version go1.20.14 linux/amd64'`. The version itself is the compiled-in constant, so the binary is a function of the source alone. |
| Same-machine reproducibility | `FILLED` | `make repro-check` → *"reproducible build OK (1.20.14 GOAMD64=v1)"* (builds twice, `cmp`) |
| Source-only reproducibility | `FILLED` | **Measured across a git checkout and a git-free export of the same source**: identical digests for all three binaries (see [§5](#5-binaries)). On the canonical tree the same test produced **different** binaries (`md5 1e3623d3…` vs `f255781b…`) and version strings (`ela-premerge-baseline-2526a6b-14-g2109` vs empty) — the defect `273469d` fixes. |
| Cross-builder reproducibility | **`OPEN`** | Not attempted. A second, independent builder should reproduce the digests in [§5](#5-binaries) byte-for-byte before the tag is published. |
| Build container / SOURCE_DATE_EPOCH | **`OPEN`** | No container image is pinned; the build is a bare `make release` with the environment above. |

---

## 4. Dependencies

| Field | Status | Value |
|---|---|---|
| Module path | `FILLED` | `github.com/elastos/Elastos.ELA` |
| Go language version | `FILLED` | `go 1.20` (`go.mod`) |
| `sha256(go.mod)` | `FILLED` | `ba468c7ae64fa5a0eae0dfa8184759dd9083a97225827dbdcadc828609651dd5` |
| `sha256(go.sum)` | `FILLED` | `990f6fcdd09e58efb80b321a1f08cf6808d82076f8b4d9bf48227e542a1dd8b4` (95 lines) |
| Dependency integrity | `FILLED` | `go mod verify` → **"all modules verified"**, offline, against the on-box module cache |
| Direct requirements | `FILLED` | 15 direct + 34 indirect, unchanged from the root snapshot `d8488bf` — **no dependency was added, removed or bumped in this release** (`F-211`: dependency bumps deliberately do not belong in a consensus batch) |
| Module cache used | `FILLED` | `/root/go/pkg/mod` (325 MB), sufficient for a complete offline build |
| Full module-graph digest (`go list -m all`) | **`OPEN`** | Not producible offline: `go.sum` is pruned to what the build needs (normal for Go 1.20 graph pruning), so `go list -m all` fails with *"missing go.sum entry for go.mod file"* for `github.com/pelletier/go-toml@v1.9.5`. `go.sum` + `go mod verify` is the attestation that is actually available; a full graph digest would require network access, which is forbidden. |
| Vendoring | `FILLED` | None (`/vendor` is git-ignored and absent) |
| Third-party CVE review | **`OPEN`** | `F-211` was closed with "no CVE and no defect proven" on inspection; no scanner was run and none can be, offline. |
| `go.sum` shipped with the release archive | **`OPEN`** | `go.sum` is `.gitignore`d in this tree (`/go.sum`). A source archive must carry it explicitly or the release is not buildable from source. **This is a real packaging hazard — a fresh clone does not build without it.** |

---

## 5. Binaries

Built with `make release` (`GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 go
build -ldflags "-X 'main.GoVersion=go version go1.20.14 linux/amd64'" -trimpath`),
toolchain and environment exactly as in [§3](#3-go-toolchain-attestation).

| Binary | Status | sha256 | Size (bytes) | `--version` |
|---|---|---|---|---|
| `ela` | `FILLED`¹ | `5b768eb28e2aa1a07e7f61654f1167408ad17fa68e3465b3e6f8264c6d0535de` | 26 097 107 | `ela-v1.0.0 go version go1.20.14 linux/amd64` |
| `ela-cli` | `FILLED`¹ | `d10d15b596535a6ff82eb75b86c8002b8856d63067136fef5a2c5f6854ae999f` | 25 459 306 | `ela-cli version v1.0.0` |
| `ela-dns` | `FILLED`¹ | `139015bf577808f819bfba72f063dbb423f9a2fb4e0660dbcbc34d5171628204` | 8 313 900 | `ela-dns version v1.0.0` |

¹ Measured at the pre-merge tree state in [§1](#1-identity). Adding
`CHANGELOG.md` and this file does not affect the binaries (no Go source
changes), but **any** further source change does. Re-measure after merge.

md5 equivalents, for cross-checking against the reproducibility evidence in
[§3](#3-go-toolchain-attestation): `ela` `6f2237642d19f231143958e0f493f403`,
`ela-cli` `3184e89d64e553050792936ef80bbc7a`, `ela-dns`
`936b76bc25eed5a2c0938d1865760fcf` — **identical from a git checkout and from a
git-free export of the same source.**

| Field | Status | Value |
|---|---|---|
| P2P user agent advertised | `FILLED` | `ela-v1.0.0` (10 bytes; the version message caps its whole payload at 82 bytes, of which 35 are fixed fields) |
| RPC `compile` field | `FILLED` | `v1.0.0` |
| Other platforms (darwin, arm64, windows) | **`OPEN`** | Not built. The `release` target pins `linux/amd64` deliberately — a consensus binary must be built for a pinned target because float contraction is architecture-dependent (F-210). Any other target needs its own reproducibility argument. |
| Detached signatures / checksum file | **`OPEN`** | No `SHA256SUMS`, no `.asc` signatures produced. |
| Container image + digest | **`OPEN`** | `docker/` exists in-tree; no image was built or pinned. |

---

## 6. Verification evidence

| Field | Status | Value |
|---|---|---|
| `go build ./...` | `FILLED` | Clean, offline, pinned toolchain |
| `gofmt` on changed files | `FILLED` | Clean |
| `go vet ./utils/version/` | `FILLED` | Clean |
| The 8 mandated suites | `FILLED` | `blockchain`, `dpos/state`, `cr/state`, `core/transaction`, `common/config`, `common/config/settings`, `utils`, `test/unit` — all `ok` at `-count=1` on the release tree |
| F-210 build-pin test | `FILLED` | `test/unit -run TestF210` → `ok` (the Makefile still carries `GOAMD64`, `-trimpath` and `repro-check:`) |
| `make repro-check` | `FILLED` | OK |
| Full recursive `go test ./...` | **`OPEN`** | Not run for this release record. Several packages carry pre-existing, documented environmental failures (`p2p/peer`, `elanet/routes`, `utils/http` socket/port tests); those must be triaged and either fixed or explicitly waived. |
| `-race` across the touched packages | **`OPEN`** | Individual commits record `-race` runs (`blockchain`, `dpos`, `dpos/state`, and the concurrency batches). No single consolidated `-race` run was performed at this tree state. |
| `revive` code-quality gate (CI step) | **`OPEN`** | Requires downloading `revive` — network access, which is forbidden here. Must run in CI. |
| Mutation / fail-on-pristine coverage | `FILLED`, with a stated limit | Recorded per commit; the largest is `bcb35d9` (45/45 production mutations discriminated) and its landing pass (35/35). **Limit, from `bcb35d9` itself:** three crash-guard tests live in packages *outside* the 8-suite gate, so removing those guards leaves the 8 suites green. Either widen the gate to `./crypto ./auxpow ./p2p/server` or add structural rows. |
| Live multi-node validation | **`OPEN`** | Partial and honestly bounded. F-015 was proven on a live armed rehearsal chain (`9d2be09`); the forced-rollback boot behaviour was measured in a 48-node rehearsal (`6ee9e5d`). **No live mesh run exists for F-093 reorg-during-emergency, for NX-06, or for the shipped fix set as a whole.** |
| Sidechain testbed | **`OPEN` (deferred by owner)** | Blocks the live proof of the F-104/F-118 mint pair. Those remain gated fixes, **not** claimed closed. |

---

## 7. Delta against released upstream v0.9.9.6

> ### Status: **OPEN and BLOCKED**
>
> **This field cannot be produced in this environment, and no substitute is
> offered.**
>
> **Why it is blocked, in two independent ways:**
>
> 1. **There is no upstream history in this repository.** The root commit
>    `d8488bf` is a **squashed snapshot** — *"ELA v0.9.9.7 + all our fixes +
>    battle/exploit tests"* — with **no parent**
>    (`git log --format='%H %P' -1 d8488bf` prints an empty parent field, and
>    `git rev-list --max-parents=0 HEAD` returns exactly `d8488bf`). No upstream
>    commit, tag, branch or blob for `v0.9.9.6` exists in this object store; the
>    only configured remote is the local canonical clone. So even a full local
>    diff is impossible: there is nothing to diff against.
> 2. **Fetching it is forbidden.** Network access is explicitly prohibited for
>    this work — no clone, no fetch, no download. Retrieving upstream
>    `v0.9.9.6` would require exactly that.
>
> **Corroborating evidence, measured in-tree:** the repository's own
> per-version release notes (`docs/release-notes/`, 35 files) stop at
> `release-notes-0.9.9.5.md`. There is **no** `release-notes-0.9.9.6.md` and no
> `0.9.9.7`. So the snapshot does not document the two versions immediately
> preceding it either — the gap is in the source tree, not only in the git
> history.
>
> **Consequence for the release, stated plainly:** the 108 commits in
> `CHANGELOG.md` are the delta against the **`d8488bf` snapshot**, not against
> released `v0.9.9.6`. Everything that went into that snapshot — the upstream
> `v0.9.9.6 → v0.9.9.7` work plus the earlier incident fixes and the
> battle/exploit test corpus — is **unaudited and unattributed by this
> changelog**. A v1.0.0 release that claims to supersede v0.9.9.6 must not
> imply that this document describes the whole difference.
>
> **What must happen to close it** (all require an environment with network
> access, and none may be done by inference):
>
> - [ ] Obtain released upstream `v0.9.9.6` from the official repository and
>       verify its tag signature.
> - [ ] Produce and review `git diff v0.9.9.6..<release tag>` for the whole
>       tree, and attach it to this manifest.
> - [ ] Reconcile that diff against `CHANGELOG.md`: every hunk must be
>       attributable either to one of the 108 commits recorded here or to the
>       pre-existing content of the `d8488bf` snapshot.
> - [ ] Record explicitly which consensus-affecting changes arrived with the
>       snapshot rather than with these 108 commits — in particular gate 1
>       (`StrictMoneyRangeHeight = 2260451`), the CrossChain-UTXO
>       freeze/restriction heights, the forced-rollback height and trigger, and
>       the frozen-address list, **all of which are inherited from `d8488bf`,
>       not introduced here**.
> - [ ] Decide, with the owner, whether v1.0.0 is the right version number for
>       a tree whose provenance below `d8488bf` is unverified.

---

## 8. Operator-facing changes that need documentation

| Field | Status | Value |
|---|---|---|
| `CHANGELOG.md` | `FILLED` | 108 commits, grouped by theme, with the two gates called out |
| Known-limits section | `FILLED` | End of `CHANGELOG.md` |
| `docs/release-notes/release-notes-1.0.0.md` | **`OPEN`** | The tree's existing per-version convention (35 files, `0.3.4` … `0.9.9.5`). Decide whether v1.0.0 also gets a note in that series — with a "How to Upgrade" section, which every one of those files has and `CHANGELOG.md` does not. |
| New CLI commands | `FILLED` | `ela-cli purgeresidue` (offline residue cleaner, node stopped) |
| Changed CLI behaviour | `FILLED` | `ela-cli rollback` now **requires** `--height` (the positional form used to print help and exit 0); `--datadir` now honours `config.json` when unset; `--conf` remains inert, so run offline commands from the node's working directory |
| New config fields | `FILLED` | `ArmIncidentGates` (non-mainnet rehearsal opt-in; **refused outright on a mainnet foundation identity**), `DPoSConfiguration.SponsorsFilePath` hardening |
| Removed endpoints | `FILLED` | REST `GET /api/v1/restart` **removed**; the node-info port no longer serves `/debug/pprof/*` |
| Node will now **refuse to start** when… | `FILLED` | …its foundation identity is mainnet but any coordinated value is not the pinned one; …the forced-rollback target block is still main-chain indexed; …a rewind marker on disk says a rollback was started that this node is not configured to finish; …the pre-flight store scan finds damage; …the block-index bucket is missing behind an authoritative chainstate record; …`FoundationAddress` is malformed. **Each is deliberate and each error text carries a remedy.** |
| Emergency failsafe latency change | `FILLED` | RevertToPOW(NoBlock) rescue latency **~2 h → ~4 h** (FV-22 option (b), `ed54844`) |
| Keystore rotation notice | **`OPEN`** | F-059: **every keystore created by any prior build is compromised at rest.** Operators must create a fresh keystore and migrate. This notice must be written and distributed; it is not in any operator-facing document yet. |
| Coordinated-disclosure decision (F-059 / F-190) | **`OPEN`** | Upstream defect affecting anyone running an earlier build. Owner decision. |
| Restart runbook | **`OPEN`** | Must include at minimum: the NX-06 below-gate residual (a node syncing from genesis can still be poisoned in the historical POW windows), the D3 view-storm item, purging `ffldb-blockidx` before restart, and the fact that gate 1 arms on the first block. |
| Config template / `docs/` update | **`OPEN`** | `docs/config.json.md` still enables REST, which is what made F-036 reachable. Not updated. |
| Upgrade path from v0.9.9.6 | **`OPEN`** | Not written. |
| Downgrade / abort plan | **`OPEN`** | Not written. A node that has completed the forced rollback and then downgrades has no defined behaviour. |

---

## 9. Sign-off

| Field | Status |
|---|---|
| Core-engineer confirmation of gate 2 (2 265 000) | **`OPEN`** |
| Core-engineer acknowledgement of the F-096 degradation-reset semantic delta (`1a5aa44`) | **`OPEN`** |
| Owner decision on F-205 and its sibling class | **`OPEN`** |
| Owner ratification of the FV-22 option (b) latency cost | `FILLED` — the owner chose option (b) (`ed54844`) |
| Release manager sign-off | **`OPEN`** |
| Security review sign-off | **`OPEN`** |

---

## 10. Re-measurement procedure

Run this on the release tree **after merge and before tagging**, and paste the
results over the provisional values above. Offline throughout.

```sh
export PATH=/usr/local/go1.20.14/bin:$PATH
export GOPROXY=off GOTOOLCHAIN=local

# 1. identity
git rev-parse HEAD
git rev-parse HEAD^{tree}
git rev-list --count d8488bf..HEAD          # expect 108 (+ the release-meta commits)

# 2. gates — expect exactly these two, and no third
grep -n 'MainNetStrictMoneyRangeHeight\|MainNetRevisedDPoSRewardHeight' \
     common/config/config.go

# 3. toolchain
go version; go env GOVERSION GOROOT GOAMD64 CGO_ENABLED
sha256sum "$(go env GOROOT)/bin/go"
cat .go-version

# 4. dependencies
sha256sum go.mod go.sum
go mod verify                                # expect: all modules verified

# 5. binaries
make release
sha256sum ela ela-cli ela-dns
stat -c '%n %s' ela ela-cli ela-dns
./ela --version; ./ela-cli --version; ./ela-dns -v

# 6. verification
make repro-check
go test -count=1 ./blockchain/ ./dpos/state/ ./cr/state/ ./core/transaction/ \
                 ./common/config/ ./common/config/settings/ ./utils/ ./test/unit/
```

Source-only reproducibility (the check `repro-check` cannot perform, because it
builds twice on one machine):

```sh
# build from a git-FREE export and confirm the digests are identical
mkdir /tmp/exp && tar --exclude=.git --exclude=ela --exclude=ela-cli \
    --exclude=ela-dns -cf - . | (cd /tmp/exp && tar xf -)
cd /tmp/exp && make release && sha256sum ela ela-cli ela-dns
```
