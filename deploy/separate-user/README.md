# Separate-user deployment

By default the Atlas MCP server runs as the same OS user as Claude Code, the agent it governs. That user can then read and change everything Atlas keeps: the audit log, the credential registry, the issuer signing key, agent keys, and the secrets in the MCP config. Signatures and in-memory pinning limit what it can do during a session, but changes take effect at the next restart (SPEC Appendix H).

This deployment runs the gatekeeper as its own system user, so the agent can start it and talk to it over stdio but can't touch its state.

| What | Where | Owner / mode | Agent user can |
|---|---|---|---|
| Code | `/opt/atlas-protocol` | root, no group/other write | read, run via the launcher only |
| State (audit log, registry, keys) | `/var/lib/atlas-protocol` | `atlas`, 0700 | nothing |
| Settings and secrets | `/etc/atlas-protocol/atlas.env` | `root:atlas`, 0640 | nothing |
| Launcher | `/usr/local/libexec/atlas-gatekeeper` | root, 0755 | run as `atlas` via sudo, no arguments |

Claude Code starts the server with `sudo -n -u atlas /usr/local/libexec/atlas-gatekeeper`. The sudoers rule allows exactly that command with no arguments, and sudo resets the environment, so the agent's MCP config can't inject settings or flags. The launcher reads the settings from `atlas.env`.

## Prerequisite: the agent user must not be root-equivalent

Separation only holds if the agent user can't become root or `atlas`. Check the agent user for:

- passwordless `sudo` (any `NOPASSWD: ALL` rule)
- membership in `sudo`, `admin`, `wheel`, `docker`, `lxd`, `libvirt` or `disk`. Each of these gives root, for example by mounting `/` into a container.

If any of these apply, the agent can read `/var/lib/atlas-protocol` anyway, and this deployment adds little. Run Claude Code as a dedicated unprivileged user instead, or remove those rights. `verify.sh` checks all of this.

## Install

From a checkout you have reviewed (not a working tree the agent can write to: its `dist/` and `node_modules/` are what will run as the gatekeeper):

```sh
npm ci && npm run build
sudo sh deploy/separate-user/install.sh AGENT_USER                     # fresh state
sudo sh deploy/separate-user/install.sh AGENT_USER --migrate-from ~AGENT_USER/.atlas-protocol
```

The installer also refuses a Node binary that isn't owned by root, such as Homebrew/linuxbrew or nvm builds: a user-writable Node would run as the gatekeeper. Pass `NODE=/path/to/root-owned/node` if it isn't `/usr/bin/node` or `/usr/local/bin/node`.

Then:

1. Put the `ATLAS_*` settings in `/etc/atlas-protocol/atlas.env` (as root). Keep `ATLAS_REQUIRE_ISOLATION=true`, so the server refuses to start if the self-check fails.
2. Replace the agent's MCP server entry with the one the installer prints, with no `env` block:
   ```json
   "atlas-protocol": {
     "command": "sudo",
     "args": ["-n", "-u", "atlas", "/usr/local/libexec/atlas-gatekeeper"]
   }
   ```
3. Reconnect, then run as the agent user:
   ```sh
   sh deploy/separate-user/verify.sh
   ```
   `atlas_status` should show `isolation.isolated: true`.

To upgrade, rebuild and re-run `install.sh`. It replaces `/opt/atlas-protocol` and leaves the state and `atlas.env` alone.

## After migrating

The agent user could read everything in the old data directory and the old MCP config, so treat those secrets as exposed:

- **Issuer key:** rotate it with `atlas_key_rotate`. Existing credentials are re-signed, and old audit signatures still verify against the archived public key.
- **HMAC secret:** rotate the audit log first (`atlas_audit_rotate`), then set a new `ATLAS_HMAC_SECRET`. Keep the old secret offline if you need to re-check the archived log's HMACs.
- **Agent keys and the keystore passphrase:** delete `/var/lib/atlas-protocol/agent-keys/`, set a new `ATLAS_KEYSTORE_PASSPHRASE`, and register fresh credentials. A different passphrase can't open the old keystore, so set it before the first start.
- **Telegram bot token:** revoke it with @BotFather and set the new one.
- Remove the `ATLAS_*` values from the agent's MCP config, and delete the old data directory once the new server is verified.

The operator key is encrypted under the operator's passphrase, which is typed at a terminal, so it doesn't need rotating unless that passphrase was exposed.

## Operator commands

Operator commands now run as `atlas`, through the operator's own sudo rights (not the agent's rule):

```sh
atlas-operator attach --agent did:atlas:...
atlas-operator break-glass --reason "..."
sudo cat /var/lib/atlas-protocol/bootstrap-code.txt   # first registration's confirmation code
```

## Limits

- The self-check (`src/isolation.ts`) inspects top-level ownership and modes: the data dir, the package root, `dist/`, `node_modules/` and the Node binary. The installer sets these recursively. Changes made later by root aren't re-verified file by file.
- The agent can still start its own gatekeeper instance through the launcher. That instance has the same state and the same rules, so it gains nothing a reconnect wouldn't.
- The issuer key is still stored in plaintext inside the 0700 data dir; #45 tracks encrypting it.
