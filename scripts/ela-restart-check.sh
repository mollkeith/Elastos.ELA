#!/usr/bin/env bash
#
# ela-restart-check.sh -- run this BEFORE you start your ELA node on restart day.
#
# For operators who do NOT use the node manager: exchanges, block explorers,
# mining pools, RPC providers, anyone running `ela` directly or under systemd.
# (node.sh users can run `node.sh ela preflight`, which performs these same
# checks plus a few it can only do itself.)
#
# It is READ-ONLY. It starts nothing, stops nothing, and writes nothing to the
# chain store. Safe to run as often as you like.
#
# The chain-state prediction comes from `ela-cli preflight`, which reads the
# block store directly. This script adds the checks that live outside the
# binary: is the node stopped, is there a backup, is there disk headroom, is
# the clock sane, are the consensus ports reachable.
#
#   usage:  ./ela-restart-check.sh [--datadir <path>] [--bin-dir <path>] [--json]
#
# EXIT CODES
#   0  ready to start
#   1  usage or environment problem (this script could not do its job)
#   2  no readable chain store at the given path
#   3  the node is still RUNNING -- stop it first
#   4  the node WILL REFUSE to start -- fix the reported cause
#   5  internal error
#   6  ready, but a check outside the chain store needs your attention
#
set -uo pipefail

DATADIR=""; BINDIR=""; JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    --datadir) DATADIR="${2:-}"; shift 2 ;;
    --bin-dir) BINDIR="${2:-}";  shift 2 ;;
    --json)    JSON=1; shift ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

RED=$'\033[0;31m'; YEL=$'\033[0;33m'; GRN=$'\033[0;32m'; BLD=$'\033[1m'; OFF=$'\033[0m'
[ -t 1 ] || { RED=""; YEL=""; GRN=""; BLD=""; OFF=""; }

WARN_COUNT=0
say()  { [ "$JSON" = 1 ] || printf '%s\n' "$*"; }
ok()   { say "  ${GRN}OK${OFF}      $*"; }
warn() { WARN_COUNT=$((WARN_COUNT+1)); say "  ${YEL}ATTENTION${OFF}  $*"; }
bad()  { say "  ${RED}PROBLEM${OFF}  $*"; }
hdr()  { say ""; say "${BLD}$*${OFF}"; }

# ---------------------------------------------------------------- locate things
if [ -z "$BINDIR" ]; then
  for c in . ./ela ~/node/ela /usr/local/bin; do
    [ -x "$c/ela-cli" ] && { BINDIR="$c"; break; }
  done
fi
[ -n "$BINDIR" ] && [ -x "$BINDIR/ela-cli" ] || {
  echo "ela-restart-check: cannot find ela-cli. Pass --bin-dir <path to the directory holding ela and ela-cli>." >&2
  exit 1
}
CLI="$BINDIR/ela-cli"; ELA="$BINDIR/ela"

# The datadir is the directory that CONTAINS data/ and logs/ -- not data/ itself.
if [ -z "$DATADIR" ]; then
  for c in ./elastos ~/node/ela/elastos ./ela/elastos; do
    [ -d "$c/data" ] && { DATADIR="$c"; break; }
  done
fi
[ -n "$DATADIR" ] && [ -d "$DATADIR/data" ] || {
  echo "ela-restart-check: cannot find the chain store. Pass --datadir <path> -- the directory that CONTAINS data/ (not data/ itself)." >&2
  exit 2
}

say "=============================================================================="
say "${BLD}ELA RESTART PRE-FLIGHT${OFF}   -- read-only.  Run this BEFORE starting the node."
say "=============================================================================="
say "  binaries : $BINDIR"
say "  datadir  : $DATADIR"

# ---------------------------------------------------------------- 1. node stopped
#
# Ask "is a node using THIS store", not "does any ela process exist". A host can
# legitimately run several nodes (or an unrelated one), and a global pgrep would
# refuse to check a store that is perfectly idle. The authority is the lock on
# this data directory, so we look for a process holding a file under it, and
# leave the final say to `ela-cli preflight`, which fails with exit 3 if it
# cannot take the shared lock.
hdr "1. Is a node using THIS chain store?"
ABS_DD=$(cd "$DATADIR" 2>/dev/null && pwd -P) || ABS_DD="$DATADIR"
HOLDER=""
if command -v pgrep >/dev/null 2>&1; then
  for pid in $(pgrep -x ela 2>/dev/null); do
    # a process holding this store has a file open under it, or is rooted there
    if ls -l /proc/"$pid"/fd 2>/dev/null | grep -q " ${ABS_DD}/"; then HOLDER="$pid"; break; fi
    pcwd=$(readlink -f /proc/"$pid"/cwd 2>/dev/null)
    case "$pcwd" in "$ABS_DD"|"$ABS_DD"/*) HOLDER="$pid"; break ;; esac
  done
fi
if [ -n "$HOLDER" ]; then
  bad "an ELA node (pid $HOLDER) is using this chain store. Stop it before starting the recovery."
  say ""
  say "  The store is locked while it runs, so nothing below can be checked."
  say "  Stop it the way you normally do, then run this again."
  exit 3
fi
OTHERS=$(pgrep -x ela 2>/dev/null | wc -l | tr -d ' ')
if [ "${OTHERS:-0}" -gt 0 ]; then
  ok "no node is using this store ($OTHERS other ela process(es) on this host, using other stores)"
else
  ok "no ela process is running"
fi

# ---------------------------------------------------------------- 2. the binary
hdr "2. The binary you are about to start"
if [ -x "$ELA" ]; then
  VER=$("$ELA" --version 2>/dev/null | head -1)
  [ -n "$VER" ] || VER=$("$CLI" --version 2>/dev/null | head -1)
  if printf '%s' "$VER" | grep -q 'v1\.'; then
    ok "$VER"
  else
    warn "version reports: ${VER:-<none>}"
    say "            The recovery only happens on the release build. If this is not it,"
    say "            update the binary before you start."
  fi
  say "            sha256  $(sha256sum "$ELA" 2>/dev/null | cut -c1-64)"
  say "            Compare that against the published checksum for the release."
else
  warn "no 'ela' binary next to ela-cli -- cannot report its version or checksum"
fi

# ---------------------------------------------------------------- 3. backup
hdr "3. Is there a backup? (the rewind is destructive and cannot be undone)"
FOUND_BK=""
for p in "$DATADIR/../elastos.bak"* "$DATADIR.bak"* "$DATADIR/../*.tgz" "$DATADIR/../*.tar.gz"; do
  [ -e "$p" ] && FOUND_BK="$FOUND_BK $p"
done
if [ -n "$FOUND_BK" ]; then
  ok "possible backup(s) found:$FOUND_BK"
  say "            Confirm one is a COMPLETE copy of $DATADIR taken while the node was stopped."
else
  warn "no backup of the data directory found next to it"
  say "            The rewind permanently discards blocks. With the node stopped:"
  say "              cp -a \"$DATADIR\" \"${DATADIR}.bak\"      # or tar it to another disk"
fi

# ---------------------------------------------------------------- 4. disk
hdr "4. Disk headroom"
SZ_KB=$(du -sk "$DATADIR" 2>/dev/null | awk '{print $1}')
AV_KB=$(df -Pk "$DATADIR" 2>/dev/null | awk 'NR==2{print $4}')
if [ -n "$SZ_KB" ] && [ -n "$AV_KB" ]; then
  say "            store $((SZ_KB/1024/1024)) GiB   free $((AV_KB/1024/1024)) GiB"
  if [ "$AV_KB" -lt "$((SZ_KB/5))" ]; then
    warn "less than 20% of the store size is free -- tight for a rewind plus a backup"
  else
    ok "enough free space"
  fi
else
  warn "could not measure disk usage"
fi

# ---------------------------------------------------------------- 5. clock
hdr "5. Clock"
if command -v timedatectl >/dev/null 2>&1; then
  SYNC=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  if [ "$SYNC" = "yes" ]; then ok "system clock is NTP-synchronised"
  else warn "system clock is NOT NTP-synchronised -- consensus is time-sensitive"; fi
else
  warn "timedatectl unavailable -- check the clock yourself; consensus is time-sensitive"
fi

# ---------------------------------------------------------------- 6. ports
hdr "6. Consensus ports (20338 P2P, 20339 DPoS)"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
  for p in 20338 20339; do
    if ufw status 2>/dev/null | grep -q "^$p"; then ok "$p allowed in ufw"
    else warn "$p not found in the ufw allow list -- a producer unreachable on 20339 gets marked inactive"; fi
  done
else
  say "            ufw is not active or not installed -- check your cloud firewall instead."
  say "            20338/tcp and 20339/tcp must be reachable from the internet."
fi

# ---------------------------------------------------------------- 7. the prediction
hdr "7. What will happen when you start -- from the node's own store"
if [ "$JSON" = 1 ]; then
  "$CLI" preflight --datadir "$DATADIR" --json
  PF=$?
  exit $PF
fi
say ""
"$CLI" preflight --datadir "$DATADIR"
PF=$?

say ""
say "=============================================================================="
case "$PF" in
  0) if [ "$WARN_COUNT" -gt 0 ]; then
       say "${YEL}READY -- but $WARN_COUNT item(s) above need your attention first.${OFF}"
       exit 6
     fi
     say "${GRN}READY TO START.${OFF}"; exit 0 ;;
  2) say "${RED}NO READABLE CHAIN STORE.${OFF} Check --datadir."; exit 2 ;;
  3) say "${RED}THE NODE IS RUNNING.${OFF} Stop it and run this again."; exit 3 ;;
  4) say "${RED}THE NODE WILL REFUSE TO START.${OFF} Fix the cause reported above; do NOT start it yet."; exit 4 ;;
  1) say "${RED}CONFIGURATION PROBLEM.${OFF} See above."; exit 1 ;;
  *) say "${RED}INTERNAL ERROR from ela-cli preflight (exit $PF).${OFF}"; exit 5 ;;
esac
