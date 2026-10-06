# SSH Diagnostics

[![SSH Diagnostics](media/thumbnail.webp)](media/cover.png)

<!-- block-metadata:start -->
[![Block version: 0.1.0](https://img.shields.io/badge/block-0.1.0-blue)](model.json)
[![BloxSmith compatibility: 1.0.9](https://img.shields.io/badge/BloxSmith-1.0.9-brightgreen)](compatibility.json)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Verified BloxSmith versions: **1.0.9** (bundled-block tests; see [test evidence](compatibility.json)).
<!-- block-metadata:end -->

## Role

Run a selected **read-only Linux diagnostic** on an explicitly approved SSH host. The block owns the encrypted connection, verifies the pinned host key before authentication, collects a bounded complete result and filters sensitive text before publishing it. It does not accept shell scripts, arbitrary executables, hostnames or credentials from an input.

SSH access is **disabled by default**. Adding the block, preparing a Run or opening its settings never authenticates or executes a remote command. Use only hosts you are authorized to diagnose and a dedicated non-root account with minimal server-side permissions.

## Ports

Input **`request`**:

```json
{"request_id":"health-1","host":"application","command":"uptime","args":{}}
```

The host is a configured alias. The command is a configured profile ID, not shell text. `request_id` is optional correlation; it is not an idempotency key. Every delivered request executes once when scheduled, including deliberate repeats. There are no automatic retries or persistent SSH sessions.

| Output | Contents |
| --- | --- |
| `result` | Request/host/profile identity, exit code, completion, duration and safe diagnostic code. |
| `stdout` | Complete bounded stdout with credential/control-sequence filtering. |
| `stderr` | Complete bounded stderr with the same filtering. |

Errors, cancellation and output-limit violations publish empty text outputs, clearing previous cached text. A nonzero remote exit code produces `remote_error` with its complete filtered text. Missing exit status or a disconnected channel is never reported as a successful diagnostic. `executed` is true after SSH exec acknowledgement, false before any exec attempt, or null when execution is uncertain. `remote_completion_unknown` distinguishes a lost or cancelled result from a verified completion.

## Approved hosts

Configure **Approved hosts and profiles (JSON)** in the modal or inspector:

```json
[
  {
    "id":"application",
    "hostname":"app.example.test",
    "port":22,
    "username":"diagnostic",
    "host_key_sha256":"SHA256:REPLACE_WITH_VERIFIED_HOST_KEY_FINGERPRINT",
    "auth":"wallet",
    "credential_ref":"secret://workspace/ssh_application",
    "commands":["uptime","system","memory","disk","processes","service","journal"],
    "paths":{"root":"/","data":"/srv/data"},
    "services":["application.service"]
  }
]
```

The example fingerprint is deliberately not a valid placeholder credential: replace it with the **out-of-band verified** OpenSSH SHA-256 fingerprint. The block refuses unknown or changed host keys; it never trusts a first contact automatically and does not edit `known_hosts`. A host that negotiates a different key requires explicit reconfiguration. Up to 16 hosts are supported. Private SSH configuration, proxy commands and personal key files are never searched.

### Diagnostic profiles

| Profile | Controlled arguments | Remote program |
| --- | --- | --- |
| `system` | None | `/usr/bin/uname -s -r -m` |
| `uptime` | None | `/usr/bin/uptime` |
| `memory` | None | `/usr/bin/free -b` |
| `processes` | None | `/usr/bin/ps -eo pid,ppid,stat,comm` — no process argument strings. |
| `disk` | `path`: configured path alias | `/usr/bin/df -P -- APPROVED_PATH` |
| `service` | `service`: exact permitted `.service` name | `systemctl show`, limited to ID/load/active/substate/result/exit-status properties, without pager. |
| `journal` | `service`: exact permitted name; optional `lines` from 1 to 200 | `journalctl`, bounded line count, no pager or follow mode. |

SSH exec requires a command string: every argument is quoted by the block from fixed profile definitions and validated allowlists. No input can add flags, environment variables, shell operators, redirections or executable paths. Remote Linux programs and the account's login environment must be trusted; SSH transport alone cannot turn a malicious remote shell into a safe one. These profiles do not invoke system changes or elevation, but normal SSH/login/audit logs may still be written by the server.

## Authentication

### Wallet

The configured reference resolves to one of these JSON objects:

```json
{"password":"WALLET_ONLY"}
```

```json
{"private_key":"-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----","passphrase":"OPTIONAL_WALLET_ONLY"}
```

Keys are parsed in memory, not saved to disk. Supported key families: Ed25519, ECDSA and RSA of at least 2048 bits. Password authentication does not fall back to keyboard-interactive. No ambient key search, agent fallback or agent forwarding is performed. Credentials are resolved only for an executed request, passed through a private owned-process pipe and never placed in a command line.

### Explicitly authorized agent key

Set the host's `auth` to `agent`, leave `credential_ref` empty and supply `agent_key_sha256` for the **one public key** the block may use. Configure **Authorized SSH agent socket**, or leave it empty to use `SSH_AUTH_SOCK` from the runtime environment. This mode explicitly authorizes signing by that key, not all keys in the agent. The socket must belong to the runtime user and cannot be a symlink. Managed package hosts may not inherit your desktop agent environment; an explicit socket is more predictable. No agent is created automatically or forwarded remotely.

## Output privacy and limits

The block masks known wallet authentication values, optional additional literal secrets from wallet references, private-key blocks, credential-like lines, terminal control sequences and (by default) email addresses. Filtering is applied to both streams before graph output; partial chunks are never emitted. If either raw stream exceeds the configured byte limit, **both streams are discarded**, preventing a truncated credential prefix from being published.

This is not universal anonymization: arbitrary remote text may contain other sensitive data or misleading instructions. Treat diagnostic text as untrusted data. Prefer narrow profiles and minimal server permissions; use the Redact block for application-specific policies before forwarding reports. Errors and logs contain owned safe codes, not raw SSH exception messages.

## Execution and lifecycle

Requires **Linux, Python 3.10+ and Paramiko 5.0.0** in the runtime interpreter; install `requirements.txt` separately. Selected remote utilities must exist at the documented Linux paths. No remote installation is attempted. SSH host keys are pinned; SHA-1 key-exchange/signatures and legacy CBC ciphers are not enabled by this block. Unsupported peers fail instead of triggering an insecure fallback.

Both One Shot and Active Runtime execute real diagnostics on a received request. Each activation owns one connection and one command with bounded negotiation/total deadlines, byte limits and process memory. The framework schedules input events; the block does not add an unbounded queue or persist results/credentials in a sidecar file.

Stop/cancellation closes or kills the local helper. Linux parent-death fencing also closes the connection after abrupt package-host termination. **Closing SSH does not guarantee termination of a remote process**: servers may let a program continue. In that case the result explicitly remains uncertain and is not retried. For strictly enforced remote resource/lifetime limits, configure the diagnostic account on the server. A child process and a private pipe are not an OS security sandbox.

Modal and inspector share English/French settings, draft Apply/Cancel and locally owned inspector tabs that preserve edits. Reload an already prepared Run after changing settings.

## Tests

Tests create a disposable encrypted SSH server, ephemeral host/client keys and a separate temporary agent. They do not inspect personal SSH identities, contact production hosts or execute commands on real remote machines. Qualification covers host pinning before authentication, wallet password/key and authorized agent authentication, controlled command construction, bounded/redacted output, EOF/exit-status ordering, cancellation and framework/runtime/UI contracts. The proprietary framework harness is not redistributed.

## License and references

Block code: Apache-2.0. Paramiko is installed separately and retains its LGPL license.

- [Paramiko transport and host-key API](https://docs.paramiko.org/en/stable/api/transport.html)
- [Paramiko channel lifecycle](https://docs.paramiko.org/en/stable/api/channel.html)
- [Paramiko agent API](https://docs.paramiko.org/en/stable/api/agent.html)
- [OpenSSH manual](https://man.openbsd.org/ssh)
