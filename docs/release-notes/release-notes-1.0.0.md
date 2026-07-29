Elastos.ELA version 1.0.0 is now available from:

  <https://download.elastos.io/elastos-ela/elastos-ela-v1.0.0/>

This is a chain recovery release. It is not optional and it is not a routine
upgrade. Read the whole of "How to upgrade" before starting a node.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/elastos/Elastos.ELA/issues>

What this release does
======================

The main chain is rewound to height 2,260,450 and the defect class that
permitted the 20 July 2026 output-sum overflow is closed.

Two mainnet consensus height gates are introduced, and no others:

| Constant                  | Height    | Effect                                                         |
|---------------------------|-----------|----------------------------------------------------------------|
| `StrictMoneyRangeHeight`  | 2,260,451 | Money-range bounds and same-block conflict rules apply at and above |
| `RevisedDPoSRewardHeight` | 2,265,000 | Revised reward basis applies at and above                        |

`ForcedRollbackHeight` = 2,260,450 is the rewind target. It is not a validation
gate.

Every consensus rule change in this release is gated at one of those two
heights. Blocks at or below 2,260,450 validate exactly as they did under
v0.9.9.6. A node replaying the chain from genesis reaches the same verdict on
every retained block.

The coordinated mainnet heights are pinned in code and cannot be overridden by
configuration file or command line.

How to upgrade
==============

**Take a filesystem backup of your data directory before the first start of
this binary.** The rewind removes block index entries above 2,260,450 and there
is no downgrade path afterwards. A node that has completed the rewind and is
then downgraded has no defined behaviour.

Stop the node and wait until it has completely closed, then replace the `ela`
binary. Config, keystore and chaindata files are compatible.

On first start the node performs the rewind automatically. It takes under two
minutes on mainnet-sized data.

Block producers and CR council members: verify the rewind BEFORE enabling the
arbiter
----------------------------------------------------------------------------

This is the most important operational instruction in this release.

A node that joins consensus without having completed the rewind will stop the
chain for everyone. The remaining correct nodes do not out-vote it. This has
been reproduced on multi-node arbiter test networks: a single node in that state
halted an otherwise-correct majority, and consensus resumed only once that node
was stopped.

Start once with the arbiter disabled, confirm all three of the following, and
only then enable it:

1. The binary reports version `ela-v1.0.0`.
2. The store tip is exactly 2,260,450:

       ela-cli info getcurrentheight

3. `<datadir>/data/checkpoints/cp_txPool/` no longer contains a checkpoint above
   the rewind target. This release removes it during the rewind; earlier
   releases leave it in place, so its absence is a positive signal that the
   rewind ran under this binary.

If a node has already joined without rewinding: stop that node only. Do not stop
the correct nodes, do not delete chaindata, and do not remove any other
checkpoint directory. Confirm the remaining set resumes, complete the checks
above on the affected node offline, then start it again on its own.

All nodes must run this release before the chain reaches 2,265,000.

Keystore rotation
=================

Keystore files created by earlier releases use a weak source of randomness.
Anyone who obtains such a file can recover the master key from it offline in a
practical amount of time, and a strong passphrase does not prevent this.

This requires possession of the file. No node interface serves a keystore, and
this release closes the one adjacent path that could have leaked a password: the
unauthenticated node-info port no longer exposes Go profiling routes, which could
return the process command line.

Create a fresh keystore with this release and move funds and node registrations
to it. Treat existing keystore files, and every backup or copy of them, as
sensitive material for as long as they exist.

Verifying the binary
====================

Release binaries are built with a pinned toolchain and are reproducible. Build
from source and compare:

    PATH=/usr/local/go1.20.14/bin:$PATH GOTOOLCHAIN=local GOPROXY=off make release
    sha256sum ela

Use the `release` target. `make all` omits `-trimpath`, which embeds absolute
build paths, so it does not reproduce across machines.

Compatibility
=============

Elastos.ELA is supported and extensively tested on operating systems using the
Linux kernel. It is not recommended to use Elastos.ELA on unsupported systems.

Elastos.ELA should also work on most other Unix-like systems but is not as
frequently tested on them.

As with previously-supported CPU platforms, this release's pre-compiled
distribution provides binaries for the x86_64 platform.

Notable changes
===============

1. Forced rollback of the main chain to height 2,260,450, performed once on
   first start, before chain and checkpoint initialisation.
2. Money-range bounds applied to transaction outputs and to per-entry vote
   amounts, gated at 2,260,451.
3. Same-block conflict detection widened so that a producer owner key and a
   claimed CR node key cannot be paired within one block.
4. Revised DPoS reward basis, gated at 2,265,000.
5. Mainnet consensus parameters, block-shape limits and historic activation
   heights pinned in code and no longer overridable by local configuration.
6. Crash-hardening across payload parsing paths that were reachable before
   signature verification.
7. The unauthenticated node-info port no longer exposes Go profiling routes.
   Those routes could return the process command line, which may contain a
   keystore password.
8. `ela-cli` gains `purgeresidue`, an offline cleaner run with the node stopped.
   `ela-cli rollback` now requires an explicit `--height`.

Change log
==========

See `CHANGELOG.md` for the per-area summary. For the per-commit history use
`git log --reverse c61c9e61..HEAD`.
