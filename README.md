# buzz-host

Run a [Buzz](https://github.com/block/buzz) agent on a machine that is not your
desktop, and keep it running.

Two pieces, deliberately separate:

| | runs on | job |
|---|---|---|
| **`buzz-backend-ssh`** | your desktop | speaks Buzz's provider protocol; ships the agent over ssh |
| **`buzz-host`** | the target machine | owns the process: start at boot, restart on crash, where the logs go |

## Why two

Init systems are a local fact. `launchd` wants a plist and `launchctl
bootstrap`; systemd wants a unit and `systemctl --user enable --now`. A provider
that writes plists has to know which machine it is talking to, and grows a
branch per platform in the wrong place. `buzz-host` keeps that knowledge on the
machine it describes.

It also means the remote side is a **command**, not a shell redirect.
`ssh host 'cat > …'` assumes the far side's filesystem and assumes a
non-interactive shell has a useful PATH — it does not; it gets
`PATH=/usr/bin:/bin:/usr/sbin:/sbin`.

## What it does not know

Anything about containers, harnesses or MCP. The deploy payload carries
`agent_command` and `env_vars`, and both pass through untouched. So "run it over
there" and "run it in a container" stay independent choices that compose: point
the harness at [hive](https://github.com/Unforced-Dev/hive) and you get a
container on the far machine; point it at `claude-agent-acp` and you get a plain
process. This program cannot tell the difference, which is the point.

## Secrets

The agent's private key arrives on **stdin**, lands in a `0600` JSON file, and
is read back at start time by `buzz-host run`. It is never in a unit file (a
plist is world-readable), never in `argv` (visible in `ps` to every user on the
box), and never in shell history.

## Install

On the machine that will run agents:

```sh
cargo build --release -p buzz-host
install -m 755 target/release/buzz-host ~/.local/bin/
```

It needs `buzz-acp` too — from a Buzz install
(`/Applications/Buzz.app/Contents/MacOS/buzz-acp`) or built from source. Set
`BUZZ_ACP_BIN` if it lives somewhere unusual; `buzz-host paths` shows what was
found.

On your desktop:

```sh
cargo build --release -p buzz-backend-ssh
install -m 755 target/release/buzz-backend-ssh ~/.local/bin/
```

Restart Buzz. The agent dialog gains a **Run on** selector; choose
`Another machine (over SSH)` and set the host.

## Use

```sh
buzz-host list              # agents on this machine, and whether each is running
buzz-host status <name>
buzz-host paths <name>      # where its unit, log and description live
buzz-host remove <name>     # stop and forget it; the log is kept
```

On a headless Linux host, `loginctl enable-linger $USER` is what keeps user
units running after logout.

## Notes

Redeploy is update-in-place, because Buzz's protocol has no `undeploy` and
sends the same payload again. The unit name is derived from the agent name and
a hash of the relay url, so it is stable across redeploys and distinct per
relay — the same identity on two relays is genuinely two processes, since
`BUZZ_RELAY_URL` is a scalar.
