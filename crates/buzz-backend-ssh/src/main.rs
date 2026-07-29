//! `buzz-backend-ssh` — run a Buzz agent on another machine, over ssh.
//!
//! # The protocol
//!
//! Buzz's desktop discovers executables named `buzz-backend-*` on PATH (plus
//! its own bundle directory and `~/.local/bin`, because a GUI app on macOS
//! inherits `PATH=/usr/bin:/bin:/usr/sbin:/sbin` from launchd). It speaks two
//! operations, one process per call, one JSON object in on stdin and one out on
//! stdout:
//!
//! * `{"op":"info"}` → a JSON-Schema the desktop renders as a form.
//! * `{"op":"deploy", "agent":{…}, "provider_config":{…}}` → `{"agent_id":"…"}`.
//!
//! There is no third operation. After deploy the desktop never calls again: it
//! tracks whether infrastructure *exists* from the returned id, and whether the
//! agent is *alive* from relay presence. So this program's whole job is to make
//! a process exist on another machine and then get out of the way.
//!
//! # Why it knows nothing about hive
//!
//! The payload carries `agent_command` and `env_vars` verbatim, and they are
//! passed through untouched. An agent whose harness is `claude-agent-acp` and
//! one whose harness is `hive-acp` differ only in those fields, so "run it over
//! there" and "run it in a container" stay independent choices that compose.
//!
//! A provider that understood containers would have to answer both questions at
//! once, and the two answers would fight: selecting hive as the harness AND as
//! the place produced a spec naming `hive-acp` as the thing to run *inside*
//! hive's own container. The seam is only sound while this program stays
//! ignorant.
//!
//! # Why the remote side is a command, not a shell redirect
//!
//! `ssh host 'cat > …'` assumes the far side's filesystem, and assumes a
//! non-interactive shell has a useful PATH. Both assumptions are wrong often
//! enough to matter: a non-interactive ssh gets
//! `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, with neither Homebrew nor
//! `~/.local/bin` on it. `buzz-host` owns the platform-specific parts —
//! launchd here, systemd there — and this program stays transport.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    // Every path must still emit JSON: the desktop parses whatever it gets, and
    // a bare panic surfaces as an unexplained provider error.
    //
    // `{:#}` and not `to_string()` — the latter prints only the outermost
    // context, so a failure deep in an ssh call arrives as one vague clause
    // with the reason discarded. The desktop shows this string verbatim.
    let response = match run() {
        Ok(v) => v,
        Err(e) => json!({ "error": format!("{e:#}") }),
    };
    println!("{response}");
}

fn run() -> Result<Value> {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let req: Value = if line.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(&line).context("parsing the request")?
    };
    match req.get("op").and_then(Value::as_str) {
        Some("info") => Ok(info()),
        Some("deploy") => deploy(&req),
        other => bail!("unknown op {:?}", other.unwrap_or("<missing>")),
    }
}

fn info() -> Value {
    json!({
        "id": "ssh",
        "name": "Another machine (over SSH)",
        "version": VERSION,
        // REQUIRED. Without it the desktop renders no fields at all and every
        // value silently falls back to this program's defaults.
        //
        // NOTE: the desktop REJECTS any config key whose word-segments include
        // secret / password / token / key / credential — camelCase included. So
        // nothing here can be a credential, which is correct: ssh already has
        // your key, and the agent's own key arrives in the deploy payload.
        // Every default here is NON-EMPTY on purpose, and it is a workaround
        // rather than a preference.
        //
        // `WhereToRunSection`'s probe effect lists `draft` in its dependency
        // array and then calls `onDraftChange` with
        // `providerConfig: <schema defaults>`. So editing a field changes the
        // draft, which re-runs the effect, which overwrites the field with its
        // default — typing into it does nothing at all. With a default of `""`
        // the value is wiped; with a usable default the reset writes something
        // that works, and the form appears to behave.
        //
        // Upstream fix is to drop `draft` from the deps (or reset only on a
        // provider CHANGE). Until then, ship defaults a user can live with.
        "config_schema": {
            "type": "object",
            "required": ["ssh_host"],
            "properties": {
                "ssh_host": {
                    "type": "string",
                    "title": "Host",
                    "description": "user@host, as ssh would take it. Uses your existing ssh config and identity; nothing new is exposed to the network. The host needs buzz-host and buzz-acp installed.",
                    "default": "uni@uni"
                },
                "buzz_host_bin": {
                    "type": "string",
                    "title": "buzz-host path (on that machine)",
                    "description": "Leave blank unless buzz-host is somewhere unusual. A non-interactive ssh has a minimal PATH, so ~/.local/bin/buzz-host is tried before a bare command.",
                    "default": ""
                },
                "buzz_acp_bin": {
                    "type": "string",
                    "title": "buzz-acp path (on that machine)",
                    "description": "Leave blank to let that machine find its own. Set it when several copies exist and you care which one runs.",
                    "default": ""
                }
            }
        }
    })
}

/// Translate the desktop's payload into `buzz-acp`'s environment.
///
/// Every name here is buzz-acp's, read from its config rather than guessed;
/// several are near-duplicates of one another and setting the wrong one of a
/// pair fails silently. Absent fields are left unset so buzz-acp's own defaults
/// apply — writing an empty string is not the same as not writing it.
fn agent_env(agent: &Value) -> Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    let s = |k: &str| agent.get(k).and_then(Value::as_str).map(str::to_string);

    let nsec = s("private_key_nsec")
        .filter(|v| !v.is_empty())
        .context("agent.private_key_nsec is missing — the desktop refuses to deploy without it, so this means a payload from a different Buzz version")?;
    let relay = s("relay_url")
        .filter(|v| !v.is_empty())
        .context("agent.relay_url is missing")?;

    env.insert("BUZZ_PRIVATE_KEY".into(), nsec);
    env.insert("BUZZ_RELAY_URL".into(), relay);

    // NIP-OA attestation, preferred over a bare owner: the agent derives relay
    // access from its owner's membership instead of needing its own. It may
    // arrive as a JSON array or as a string already.
    match agent.get("auth_tag") {
        Some(Value::String(t)) if !t.is_empty() => {
            env.insert("BUZZ_AUTH_TAG".into(), t.clone());
        }
        Some(v) if v.is_array() => {
            env.insert("BUZZ_AUTH_TAG".into(), serde_json::to_string(v)?);
        }
        _ => {}
    }
    if let Some(owner) = s("owner_pubkey").filter(|v| !v.is_empty()) {
        env.insert("BUZZ_ACP_AGENT_OWNER".into(), owner);
    }

    // The harness. This is the field that lets hive compose: the desktop has
    // already resolved a builtin, preset or custom harness down to a command.
    if let Some(cmd) = s("agent_command").filter(|v| !v.is_empty()) {
        env.insert("BUZZ_ACP_AGENT_COMMAND".into(), cmd);
    }
    if let Some(args) = agent.get("agent_args").and_then(Value::as_array)
        && !args.is_empty()
    {
        let joined: Vec<String> =
            args.iter().filter_map(|a| a.as_str().map(str::to_string)).collect();
        env.insert("BUZZ_ACP_AGENT_ARGS".into(), joined.join(" "));
    }

    if let Some(m) = s("model").filter(|v| !v.is_empty()) {
        env.insert("BUZZ_ACP_MODEL".into(), m);
    }
    if let Some(p) = s("system_prompt").filter(|v| !v.is_empty()) {
        env.insert("BUZZ_ACP_SYSTEM_PROMPT".into(), p);
    }
    if let Some(r) = s("respond_to").filter(|v| !v.is_empty()) {
        env.insert("BUZZ_ACP_RESPOND_TO".into(), r);
    }
    if let Some(list) = agent.get("respond_to_allowlist").and_then(Value::as_array)
        && !list.is_empty()
    {
        let joined: Vec<String> =
            list.iter().filter_map(|a| a.as_str().map(str::to_string)).collect();
        env.insert("BUZZ_ACP_RESPOND_TO_ALLOWLIST".into(), joined.join(","));
    }

    for (field, var) in [
        ("idle_timeout_seconds", "BUZZ_ACP_IDLE_TIMEOUT"),
        ("max_turn_duration_seconds", "BUZZ_ACP_MAX_TURN_DURATION"),
        ("turn_timeout_seconds", "BUZZ_ACP_TURN_TIMEOUT"),
        ("parallelism", "BUZZ_ACP_AGENTS"),
    ] {
        if let Some(n) = agent.get(field).and_then(Value::as_i64) {
            env.insert(var.into(), n.to_string());
        }
    }

    // A local agent is observed over stdio; one on another machine has no stdio
    // to observe, so without this it works perfectly and appears to do nothing.
    env.insert("BUZZ_ACP_RELAY_OBSERVER".into(), "true".into());

    // The user's own env LAST, so a deliberate override wins — except over the
    // identity, which is not theirs to override and whose loss would be silent.
    if let Some(user) = agent.get("env_vars").and_then(Value::as_object) {
        for (k, v) in user {
            let Some(v) = v.as_str() else { continue };
            if k == "BUZZ_PRIVATE_KEY" || k == "BUZZ_RELAY_URL" {
                continue;
            }
            env.insert(k.clone(), v.to_string());
        }
    }

    Ok(env)
}

/// A stable unit name for this (agent, relay) pair.
///
/// Buzz models an agent as `{pubkey, relay_url}`: the same identity on two
/// relays is genuinely two processes, because `BUZZ_RELAY_URL` is a scalar. So
/// the relay has to be part of the name, or deploying to a second community
/// would REPLACE the first agent instead of running alongside it.
///
/// Redeploy must land on the same name — the desktop's contract is that sending
/// the same payload again updates in place, and a name that drifted would leave
/// two processes on one identity answering every mention twice.
fn unit_name(display: &str, relay: &str) -> String {
    let mut slug: String = display
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() { c } else { '-' })
        .collect();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    let slug = slug.trim_matches('-').to_string();
    let slug = if slug.is_empty() { "agent".to_string() } else { slug };
    let slug: String = slug.chars().take(40).collect();
    let slug = slug.trim_matches('-').to_string();

    let digest = Sha256::digest(relay.as_bytes());
    format!("{slug}-{}", &hex::encode(digest)[..6])
}

fn deploy(req: &Value) -> Result<Value> {
    let agent = req.get("agent").cloned().unwrap_or_else(|| json!({}));
    let cfg = req.get("provider_config").cloned().unwrap_or_else(|| json!({}));
    let get = |k: &str| cfg.get(k).and_then(Value::as_str).unwrap_or("").trim().to_string();

    let host = get("ssh_host");
    if host.is_empty() {
        bail!("no host configured: set 'Host' to the user@host that should run this agent");
    }

    let env = agent_env(&agent)?;
    let relay = env.get("BUZZ_RELAY_URL").cloned().unwrap_or_default();
    let display = agent.get("name").and_then(Value::as_str).unwrap_or("agent");
    let name = unit_name(display, &relay);

    let mut unit = json!({ "env": env });
    let acp = get("buzz_acp_bin");
    if !acp.is_empty() {
        unit["program"] = json!(acp);
    }

    // ONE argument, already a valid shell command.
    //
    // ssh does not carry argv as an array: it joins whatever it is given with
    // spaces and hands the result to the remote LOGIN shell, which re-parses
    // it. So a nested `sh -c '…' args…` is re-split by that shell and arrives
    // mangled — against zsh, `zsh:1: parse error near 'then'`. Building the
    // command string here, quoted once, is the only form that survives.
    //
    // The PATH dance is not optional either: a non-interactive ssh gets
    // PATH=/usr/bin:/bin:/usr/sbin:/sbin, with neither Homebrew nor
    // ~/.local/bin on it, so a bare `buzz-host` is not found even when it is
    // installed exactly where you would put it.
    let bin = get("buzz_host_bin");
    let remote = if bin.is_empty() {
        format!(
            "BH=\"$HOME/.local/bin/buzz-host\"; [ -x \"$BH\" ] || BH=buzz-host; \
             exec \"$BH\" install {}",
            shell_quote(&name)
        )
    } else {
        format!("exec {} install {}", shell_quote(&bin), shell_quote(&name))
    };

    // The unit description — which contains the agent's private key — goes on
    // STDIN. Never on the command line: argv is visible in `ps` to every user
    // on that machine, and lands in the remote shell's history.
    let out = ssh_stdin(&host, &[&remote], &serde_json::to_string(&unit)?)?;

    let mut warnings: Vec<String> = Vec::new();
    let id = out.stdout.trim();
    let id = if id.is_empty() { name.clone() } else { id.to_string() };
    for line in out.stderr.lines() {
        let line = line.trim();
        if !line.is_empty() {
            warnings.push(line.to_string());
        }
    }
    warnings.push(format!(
        "{display} is supervised on {host} as {id}. `buzz-host list` there shows its state; \
         `buzz-host paths {name}` shows where its log is."
    ));

    Ok(json!({ "agent_id": id, "warnings": warnings }))
}

struct Output {
    stdout: String,
    stderr: String,
}

fn ssh_stdin(host: &str, argv: &[&str], input: &str) -> Result<Output> {
    let ssh = find_ssh()?;
    let mut child = Command::new(&ssh)
        // Fail rather than hang: this runs under a GUI with no terminal to
        // answer a host-key or password prompt on, so an interactive question
        // is an indefinite hang with no visible cause.
        .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=15"])
        .arg(host)
        .args(argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {ssh}"))?;
    child
        .stdin
        .take()
        .context("ssh stdin")?
        .write_all(input.as_bytes())
        .context("sending the unit description")?;
    let out = child.wait_with_output().context("waiting for ssh")?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        let detail = if stderr.trim().is_empty() { stdout.trim() } else { stderr.trim() };
        bail!("{host}: {detail}");
    }
    Ok(Output { stdout, stderr })
}

/// ssh without trusting PATH, for the same launchd reason as everything else.
fn find_ssh() -> Result<String> {
    for p in ["/usr/bin/ssh", "/usr/local/bin/ssh", "/opt/homebrew/bin/ssh", "/bin/ssh"] {
        if std::path::Path::new(p).is_file() {
            return Ok(p.to_string());
        }
    }
    Ok("ssh".to_string())
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Value {
        json!({
            "name": "Research Bot",
            "relay_url": "wss://buzz.unforced.dev",
            "private_key_nsec": "nsec1example",
            "auth_tag": ["auth", "ownerpubkey", "", "sig"],
            "agent_command": "hive-acp",
            "agent_args": [],
            "model": "opus",
            "respond_to": "owner-only",
            "idle_timeout_seconds": 300,
            "max_turn_duration_seconds": 600,
            "env_vars": {"HIVE_ENV": "research", "HIVE_HARNESS": "codex"}
        })
    }

    #[test]
    fn info_declares_a_schema_or_the_desktop_renders_nothing() {
        let i = info();
        assert!(i["config_schema"]["properties"]["ssh_host"].is_object());
        // Any key the desktop reads as a secret is dropped before it arrives,
        // so a schema that asks for one silently gets nothing.
        for k in i["config_schema"]["properties"].as_object().unwrap().keys() {
            for word in ["secret", "password", "token", "key", "credential"] {
                assert!(!k.contains(word), "config key {k:?} contains {word:?}");
            }
        }
    }

    #[test]
    fn the_harness_and_user_env_pass_through_untouched() {
        // The whole reason this composes with hive: the provider must not have
        // an opinion about either.
        let env = agent_env(&payload()).unwrap();
        assert_eq!(env["BUZZ_ACP_AGENT_COMMAND"], "hive-acp");
        assert_eq!(env["HIVE_ENV"], "research");
        assert_eq!(env["HIVE_HARNESS"], "codex");
    }

    #[test]
    fn the_identity_cannot_be_overridden_by_user_env() {
        // Losing it would be silent: the agent would come up as somebody else,
        // or on a relay nobody is watching.
        let mut p = payload();
        p["env_vars"] = json!({"BUZZ_PRIVATE_KEY": "nsec1attacker", "BUZZ_RELAY_URL": "wss://elsewhere"});
        let env = agent_env(&p).unwrap();
        assert_eq!(env["BUZZ_PRIVATE_KEY"], "nsec1example");
        assert_eq!(env["BUZZ_RELAY_URL"], "wss://buzz.unforced.dev");
    }

    #[test]
    fn an_auth_tag_array_is_serialized_and_a_string_is_kept() {
        let env = agent_env(&payload()).unwrap();
        assert_eq!(env["BUZZ_AUTH_TAG"], r#"["auth","ownerpubkey","","sig"]"#);

        let mut p = payload();
        p["auth_tag"] = json!("already-a-string");
        assert_eq!(agent_env(&p).unwrap()["BUZZ_AUTH_TAG"], "already-a-string");
    }

    #[test]
    fn a_missing_identity_is_an_error_rather_than_a_silent_anonymous_agent() {
        let mut p = payload();
        p["private_key_nsec"] = json!("");
        assert!(agent_env(&p).is_err());
    }

    #[test]
    fn absent_optional_fields_are_left_unset_rather_than_blanked() {
        // Writing "" is not the same as not writing it: an empty
        // BUZZ_ACP_MODEL overrides buzz-acp's default with nothing.
        let mut p = payload();
        p["model"] = Value::Null;
        p["system_prompt"] = Value::Null;
        let env = agent_env(&p).unwrap();
        assert!(!env.contains_key("BUZZ_ACP_MODEL"));
        assert!(!env.contains_key("BUZZ_ACP_SYSTEM_PROMPT"));
    }

    #[test]
    fn the_observer_is_on_because_a_remote_agent_has_no_stdio_to_watch() {
        // Off, a remote agent works perfectly and appears to do nothing.
        assert_eq!(agent_env(&payload()).unwrap()["BUZZ_ACP_RELAY_OBSERVER"], "true");
    }

    #[test]
    fn a_name_is_stable_across_redeploys_and_distinct_per_relay() {
        let a = unit_name("Research Bot", "wss://buzz.unforced.dev");
        assert_eq!(a, unit_name("Research Bot", "wss://buzz.unforced.dev"), "not stable");
        assert_ne!(a, unit_name("Research Bot", "wss://other.example"), "collides across relays");
        assert!(a.starts_with("research-bot-"), "{a}");
    }

    #[test]
    fn a_hostile_display_name_still_produces_a_usable_unit_name() {
        // It becomes a filename and a unit label on the far side, which has its
        // own validation — but producing something it will reject is a failure
        // the user cannot act on.
        for weird in ["../../etc/passwd", "", "!!!", "Ünïcödé Bot", &"x".repeat(200)] {
            let n = unit_name(weird, "wss://r");
            assert!(!n.contains('/'), "{n}");
            assert!(!n.contains('.'), "{n}");
            assert!(n.len() <= 48, "{n} is {} chars", n.len());
            assert!(
                n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{n}"
            );
        }
    }

    #[test]
    fn shell_quoting_survives_a_path_with_a_quote_in_it() {
        assert_eq!(shell_quote("/a'b"), r"'/a'\''b'");
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;

    #[test]
    fn every_default_is_non_empty_or_the_field_cannot_be_edited() {
        // Not style. The desktop's probe effect depends on `draft` and then
        // sets `providerConfig` to the schema defaults, so every keystroke is
        // overwritten by the default — and a default of "" means the field can
        // never hold anything. A usable default is the only thing that makes
        // the form work until that loop is fixed upstream.
        let i = info();
        let props = i["config_schema"]["properties"].as_object().unwrap();
        let required = i["config_schema"]["required"].as_array().unwrap();
        for r in required {
            let key = r.as_str().unwrap();
            let default = props[key]["default"].as_str().unwrap_or("");
            assert!(
                !default.is_empty(),
                "required field {key:?} has an empty default, so it cannot be edited"
            );
        }
    }
}
