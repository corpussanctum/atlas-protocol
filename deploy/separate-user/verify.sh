#!/bin/sh
# Atlas Protocol — verify the separate-user deployment from the AGENT's side (#23).
#
#   sh deploy/separate-user/verify.sh            # run as the agent user, not root
#
# Exit status 0 only if every check passes. Used by CI and by operators after install.

set -u
ATLAS_USER=${ATLAS_USER:-atlas}
DATA=/var/lib/atlas-protocol
ETC=/etc/atlas-protocol
PREFIX=/opt/atlas-protocol
LAUNCHER=/usr/local/libexec/atlas-gatekeeper
HERE=$(cd "$(dirname "$0")" && pwd)
FAIL=0

pass() { echo "ok    $1"; }
fail() { echo "FAIL  $1"; FAIL=1; }
# expect_denied DESCRIPTION COMMAND...: the command must fail
expect_denied() {
  desc=$1; shift
  if "$@" >/dev/null 2>&1; then fail "$desc"; else pass "$desc"; fi
}

[ "$(id -u)" != 0 ] || { echo "run as the agent user, not root" >&2; exit 2; }
echo "Checking as $(id -un) (uid $(id -u))"

expect_denied "cannot list the data dir"             ls "$DATA"
expect_denied "cannot read the issuer key"           cat "$DATA/quantum-keypair.json"
expect_denied "cannot read the audit log"            cat "$DATA/audit.jsonl"
expect_denied "cannot append to the audit log"       sh -c "echo x >> '$DATA/audit.jsonl'"
expect_denied "cannot create files in the data dir"  touch "$DATA/agent-was-here"
expect_denied "cannot read the gatekeeper secrets"   cat "$ETC/atlas.env"
expect_denied "cannot modify the installed code"     touch "$PREFIX/dist/agent-was-here"
expect_denied "cannot replace the launcher"          touch "$LAUNCHER"
expect_denied "cannot sudo other commands as $ATLAS_USER" sudo -n -u "$ATLAS_USER" /bin/sh -c true
expect_denied "cannot pass arguments to the launcher"     sudo -n -u "$ATLAS_USER" "$LAUNCHER" --inspect
expect_denied "has no passwordless root sudo"        sudo -n true

BAD_GROUPS=
for group in sudo admin wheel docker lxd libvirt disk "$ATLAS_USER"; do
  id -nG | tr ' ' '\n' | grep -qx "$group" && BAD_GROUPS="$BAD_GROUPS $group"
done
if [ -n "$BAD_GROUPS" ]; then
  fail "not in a root-equivalent group (member of:$BAD_GROUPS)"
else
  pass "not in a root-equivalent group"
fi

# The gatekeeper itself must work through the launcher and report isolation
if node "$HERE/smoke.mjs"; then
  pass "gatekeeper runs via sudo launcher and reports isolated=true"
else
  fail "gatekeeper smoke test (see output above)"
fi

[ $FAIL = 0 ] && echo "All isolation checks passed." || echo "Isolation checks FAILED."
exit $FAIL
