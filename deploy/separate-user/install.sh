#!/bin/sh
# Atlas Protocol — install the gatekeeper under its own OS user (#23).
#
#   sudo sh deploy/separate-user/install.sh AGENT_USER [--migrate-from DIR]
#
# AGENT_USER is the account Claude Code (the governed agent) runs as.
# Run from a reviewed checkout with `npm ci && npm run build` already done.
# Do not install from a working tree the agent can write: whatever is in
# dist/ and node_modules/ here is what will run as the gatekeeper.
#
# Result:
#   /opt/atlas-protocol                code, root-owned, read-only to everyone else
#   /var/lib/atlas-protocol            state, 0700, owned by $ATLAS_USER
#   /etc/atlas-protocol/atlas.env      secrets, 0640 root:$ATLAS_USER
#   /usr/local/libexec/atlas-gatekeeper  launcher (the only thing AGENT_USER may sudo)
#   /usr/local/libexec/atlas-operator-exec + /usr/local/bin/atlas-operator
#   /etc/sudoers.d/atlas-protocol
#
# Environment overrides: ATLAS_USER (default atlas), NODE (root-owned node binary).

set -eu

die() { echo "install.sh: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root"
[ $# -ge 1 ] || die "usage: install.sh AGENT_USER [--migrate-from DIR]"
AGENT_USER=$1; shift
MIGRATE_FROM=
if [ $# -ge 2 ] && [ "$1" = "--migrate-from" ]; then MIGRATE_FROM=$2; shift 2; fi
[ $# -eq 0 ] || die "unexpected arguments: $*"

ATLAS_USER=${ATLAS_USER:-atlas}
SRC=$(cd "$(dirname "$0")/../.." && pwd)
PREFIX=/opt/atlas-protocol
DATA=/var/lib/atlas-protocol
ETC=/etc/atlas-protocol
LIBEXEC=/usr/local/libexec
SUDOERS=/etc/sudoers.d/atlas-protocol

id "$AGENT_USER" >/dev/null 2>&1 || die "agent user '$AGENT_USER' does not exist"
[ "$AGENT_USER" != "$ATLAS_USER" ] || die "agent user and gatekeeper user must differ"
[ "$AGENT_USER" != root ] || die "the agent must not run as root"
[ -f "$SRC/dist/index.js" ] && [ -f "$SRC/dist/operator-cli.js" ] || die "no build in $SRC/dist (run npm ci && npm run build)"
[ -d "$SRC/node_modules" ] || die "no node_modules in $SRC (run npm ci)"

# --- Node binary: must be root-owned and not group/other writable --------
if [ -z "${NODE:-}" ]; then
  for candidate in /usr/bin/node /usr/local/bin/node; do
    [ -x "$candidate" ] && NODE=$candidate && break
  done
fi
[ -n "${NODE:-}" ] || die "no node binary found; set NODE=/path/to/root-owned/node"
NODE=$(readlink -f "$NODE")
[ "$(stat -c %u "$NODE")" = 0 ] || die "$NODE is not owned by root (a user-writable Node would run as the gatekeeper)"
case $(stat -c %A "$NODE") in
  ?????w????|????????w?) die "$NODE is group/other writable" ;;
esac

# --- Gatekeeper user -----------------------------------------------------
if ! id "$ATLAS_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin "$ATLAS_USER"
fi
id -nG "$AGENT_USER" | tr ' ' '\n' | grep -qx "$ATLAS_USER" && die "$AGENT_USER is in group $ATLAS_USER"

# --- State ---------------------------------------------------------------
install -d -o "$ATLAS_USER" -g "$ATLAS_USER" -m 0700 "$DATA"
if [ -n "$MIGRATE_FROM" ]; then
  [ -d "$MIGRATE_FROM" ] || die "--migrate-from $MIGRATE_FROM is not a directory"
  [ -z "$(ls -A "$DATA")" ] || die "$DATA is not empty; refusing to migrate over it"
  cp -a "$MIGRATE_FROM"/. "$DATA"/
  chown -R "$ATLAS_USER:$ATLAS_USER" "$DATA"
  chmod -R go-rwx "$DATA"
  MIGRATED=1
fi

# --- Code (staged, then swapped in) --------------------------------------
rm -rf "$PREFIX.new"
install -d -m 0755 "$PREFIX.new"
cp -R "$SRC/dist" "$SRC/node_modules" "$SRC/package.json" "$PREFIX.new/"
chown -R root:root "$PREFIX.new"
chmod -R u+rwX,go+rX,go-w "$PREFIX.new"
rm -rf "$PREFIX.old"
[ -d "$PREFIX" ] && mv "$PREFIX" "$PREFIX.old"
mv "$PREFIX.new" "$PREFIX"
rm -rf "$PREFIX.old"

# --- Secrets -------------------------------------------------------------
install -d -o root -g "$ATLAS_USER" -m 0750 "$ETC"
if [ ! -f "$ETC/atlas.env" ]; then
  install -o root -g "$ATLAS_USER" -m 0640 "$SRC/deploy/separate-user/atlas.env.example" "$ETC/atlas.env"
  NEW_ENV=1
fi
chown root:"$ATLAS_USER" "$ETC/atlas.env"
chmod 0640 "$ETC/atlas.env"

# --- Launchers -----------------------------------------------------------
install -d -m 0755 "$LIBEXEC"
render() { # template destination
  sed -e "s|@NODE@|$NODE|g" -e "s|@PREFIX@|$PREFIX|g" -e "s|@DATA@|$DATA|g" \
      -e "s|@ETC@|$ETC|g" -e "s|@ATLAS_USER@|$ATLAS_USER|g" -e "s|@LIBEXEC@|$LIBEXEC|g" \
      "$SRC/deploy/separate-user/$1" > "$2.tmp"
  chown root:root "$2.tmp"
  chmod 0755 "$2.tmp"
  mv "$2.tmp" "$2"
}
render atlas-gatekeeper.in "$LIBEXEC/atlas-gatekeeper"
render atlas-operator-exec.in "$LIBEXEC/atlas-operator-exec"
render atlas-operator.in /usr/local/bin/atlas-operator

# --- sudoers: AGENT_USER may run exactly the launcher, with no arguments --
TMP_SUDOERS=$(mktemp)
sed -e "s|@AGENT_USER@|$AGENT_USER|g" -e "s|@ATLAS_USER@|$ATLAS_USER|g" -e "s|@LIBEXEC@|$LIBEXEC|g" \
    "$SRC/deploy/separate-user/sudoers.in" > "$TMP_SUDOERS"
visudo -cf "$TMP_SUDOERS" >/dev/null || { rm -f "$TMP_SUDOERS"; die "generated sudoers rule failed visudo"; }
install -o root -g root -m 0440 "$TMP_SUDOERS" "$SUDOERS"
rm -f "$TMP_SUDOERS"

cat <<EOF
Installed Atlas Protocol for agent user '$AGENT_USER' (gatekeeper user '$ATLAS_USER').

MCP server entry for $AGENT_USER (e.g. ~/.mcp.json), with no env block:

  "atlas-protocol": {
    "command": "sudo",
    "args": ["-n", "-u", "$ATLAS_USER", "$LIBEXEC/atlas-gatekeeper"]
  }

EOF
[ -n "${NEW_ENV:-}" ] && echo "Next: put the ATLAS_* settings in $ETC/atlas.env (root only), not in the agent's MCP config."
if [ -n "${MIGRATED:-}" ]; then
  echo "Migrated $MIGRATE_FROM into $DATA. The agent user could read everything there,"
  echo "so treat its secrets as exposed: follow 'After migrating' in deploy/separate-user/README.md,"
  echo "then delete $MIGRATE_FROM."
fi
echo "Verify: run 'atlas_status' and check isolation.isolated is true."
