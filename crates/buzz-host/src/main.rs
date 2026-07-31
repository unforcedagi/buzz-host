//! `buzz-host` — keep a `buzz-acp` running on this machine.
//!
//! # What this is for
//!
//! Buzz's desktop can hand an agent to a *backend provider* — "run this
//! somewhere else" — but the protocol stops at "somewhere else": it hands over
//! an nsec, a relay url, a harness command and an environment, and expects a
//! process to exist afterwards. Something has to own that process.
//!
//! This is that something, and it runs ON the target machine. A provider ships
//! it a JSON description over ssh and gets back a unit id; everything after —
//! start at boot, restart on crash, where the logs go, how to stop it — is a
//! local matter, handled locally.
//!
//! # Why the provider does not do this itself
//!
//! Because init systems are a local fact. `launchd` wants a plist in
//! `~/Library/LaunchAgents` and `launchctl bootstrap`; systemd wants a unit in
//! `~/.config/systemd/user` and `systemctl --user enable --now`. A provider that
//! writes plists is a provider that has to know which machine it is talking to,
//! and grows a branch per platform in the wrong repository.
//!
//! The same mistake in miniature: shipping a spec with
//! `ssh host 'cat > /etc/hive/agents/x.toml'` fails on a host where that
//! directory lives in a container, because the caller assumed the remote
//! filesystem looked a particular way. Sending a *command* rather than a
//! redirect is the fix, and it generalises.
//!
//! # Secrets
//!
//! The agent's private key never appears in a unit file, in `ps`, or in shell
//! history. It arrives on **stdin**, lands in a `0600` JSON file, and is read
//! back by `buzz-host run` at start time — so the unit itself contains only a
//! name. A plist is world-readable by default and a systemd unit usually is
//! too; putting an nsec in either is a mistake you make once.
//!
//! # What it deliberately does not know
//!
//! Anything about Buzz, hive, containers or harnesses. It is handed a program,
//! arguments and an environment. That keeps it useful for a plain
//! `claude-agent-acp` on a spare box, and keeps the interesting decisions in
//! the provider where they can be read.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "buzz-host", version, about = "Keep a buzz-acp running on this machine")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Install or update an agent, reading its description from stdin.
    ///
    /// Re-running with the same name replaces the description and restarts, so
    /// a provider can send the same payload twice without leaving two processes
    /// on one identity — which would answer every mention twice.
    Install {
        /// Unit name. Lowercase letters, digits, `-` and `_`.
        name: String,
    },
    /// Load an agent's description and exec it. This is what the unit runs.
    Run { name: String },
    /// Stop an agent and forget it.
    Remove { name: String },
    /// Agents this machine knows about, and whether each is running.
    List,
    /// Whether one agent is running, as an exit code and a line of text.
    Status { name: String },
    /// Where the supervisor thinks things are. For diagnosing a bad install.
    Paths { name: Option<String> },
}

/// What a provider sends. Deliberately not Buzz-shaped: a program, its
/// arguments, and an environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentUnit {
    /// Absolute path to the binary. Omitted means "find buzz-acp".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    program: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

fn main() {
    if let Err(e) = run() {
        // `{:#}` prints the whole chain. A provider forwards this string to the
        // desktop verbatim and there is nowhere else for a reader to look.
        eprintln!("buzz-host: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Cmd::Install { name } => install(name),
        Cmd::Run { name } => exec_agent(name),
        Cmd::Remove { name } => remove(name),
        Cmd::List => list(),
        Cmd::Status { name } => status(name),
        Cmd::Paths { name } => paths(name.as_deref()),
    }
}

// ── naming and layout ───────────────────────────────────────────────────────

/// A name becomes a filename, a unit label, and part of a log path. Anything
/// outside this set could escape the state directory or produce a unit label
/// that `launchctl` silently refuses.
fn check_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !ok {
        bail!(
            "invalid name {name:?}: 1-64 characters of lowercase letters, digits, '-' and '_'. \
             It becomes a filename and a unit label."
        );
    }
    Ok(())
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set, so there is nowhere to keep state")
}

/// Per-user, and on the INTERNAL disk by convention.
///
/// On macOS a launchd-spawned process is denied readdir on external volumes
/// while `stat` still succeeds — guards pass, the process hangs, and
/// `launchctl` reports it running. State that a supervisor needs at boot has no
/// business on a removable disk.
fn state_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("BUZZ_HOST_STATE") {
        return Ok(PathBuf::from(dir));
    }
    let home = home()?;
    Ok(if cfg!(target_os = "macos") {
        home.join("Library/Application Support/buzz-host")
    } else {
        home.join(".local/state/buzz-host")
    })
}

fn unit_file(name: &str) -> Result<PathBuf> {
    Ok(state_dir()?.join(format!("{name}.json")))
}

fn log_file(name: &str) -> Result<PathBuf> {
    Ok(state_dir()?.join("logs").join(format!("{name}.log")))
}

fn label(name: &str) -> String {
    format!("dev.buzz.host.{name}")
}

/// This binary's own path, for the unit to invoke.
///
/// Resolved rather than assumed: a unit that says `buzz-host` depends on a PATH
/// that launchd and systemd do not provide, and the failure — a unit that
/// exists, is enabled, and never starts — is among the least legible there is.
fn self_path() -> Result<PathBuf> {
    let p = std::env::current_exe().context("locating this binary")?;
    p.canonicalize().or(Ok(p))
}

/// Where `buzz-acp` is, without trusting PATH.
fn find_buzz_acp() -> Result<String> {
    if let Some(p) = std::env::var_os("BUZZ_ACP_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p.display().to_string());
        }
        bail!("BUZZ_ACP_BIN is set to {}, which is not a file", p.display());
    }
    let home = home()?;
    let candidates = [
        home.join(".local/bin/buzz-acp"),
        PathBuf::from("/usr/local/bin/buzz-acp"),
        PathBuf::from("/opt/homebrew/bin/buzz-acp"),
        PathBuf::from("/Applications/Buzz.app/Contents/MacOS/buzz-acp"),
        PathBuf::from("/usr/bin/buzz-acp"),
    ];
    for c in &candidates {
        if c.is_file() {
            return Ok(c.display().to_string());
        }
    }
    bail!(
        "cannot find buzz-acp. Looked in: {}. Set BUZZ_ACP_BIN to its path.",
        candidates.iter().map(|c| c.display().to_string()).collect::<Vec<_>>().join(", ")
    )
}

// ── install / run / remove ──────────────────────────────────────────────────

fn install(name: &str) -> Result<()> {
    check_name(name)?;

    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw).context("reading the unit from stdin")?;
    if raw.trim().is_empty() {
        bail!("no unit description on stdin");
    }
    let mut unit: AgentUnit = serde_json::from_str(&raw).context("parsing the unit description")?;

    // Resolve the program HERE, on the machine that will run it. A provider
    // cannot know where buzz-acp lives on a host it has never seen.
    let program = match unit.program.take() {
        Some(p) if !p.is_empty() => p,
        _ => find_buzz_acp()?,
    };
    if !Path::new(&program).is_file() {
        bail!("{program} is not a file on this machine");
    }
    unit.program = Some(program.clone());

    let dir = state_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::create_dir_all(dir.join("logs"))?;

    // Write-then-rename at 0600. The env holds the agent's private key, so the
    // file must never exist at a readable mode even briefly.
    let path = unit_file(name)?;
    let tmp = dir.join(format!(".{name}.json.tmp"));
    write_private(&tmp, serde_json::to_string_pretty(&unit)?.as_bytes())?;
    std::fs::rename(&tmp, &path).with_context(|| format!("installing {}", path.display()))?;

    let id = supervisor().install(name, &self_path()?)?;

    println!("{id}");
    eprintln!("buzz-host: {name} installed ({program})");
    eprintln!("buzz-host: logs at {}", log_file(name)?.display());
    Ok(())
}

/// Load the description and become the agent.
///
/// `exec`, not spawn: the supervisor should watch buzz-acp itself, not a parent
/// that adds nothing and hides the exit status.
fn exec_agent(name: &str) -> Result<()> {
    check_name(name)?;
    let path = unit_file(name)?;
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}; was this agent installed?", path.display()))?;
    let unit: AgentUnit = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", path.display()))?;
    let program = unit.program.clone().unwrap_or_else(|| "buzz-acp".to_string());

    let mut cmd = Command::new(&program);
    cmd.args(&unit.args);

    // Give the agent a PATH worth having, BEFORE the unit's own env so an
    // explicit PATH still wins.
    //
    // launchd hands a job `/usr/bin:/bin:/usr/sbin:/sbin` and systemd is no
    // better. buzz-acp then spawns its harness by name — `claude-agent-acp`,
    // `hive-acp` — and a harness installed in the conventional place is simply
    // not found. The failure surfaces as "agent failed to spawn: No such file
    // or directory", which reads as a missing install rather than as a PATH
    // that no login shell ever touched.
    //
    // This is exactly the sort of local knowledge that belongs here rather than
    // in a provider on some other machine.
    let path = default_path();
    cmd.env("PATH", &path);

    // Start the agent somewhere meaningful.
    //
    // launchd hands a job `/` and systemd hands it `/` too, so an agent's
    // harness opens every session in the filesystem root. That is a bad place
    // to work from and a worse place to read project context from: Claude Code
    // loads a CLAUDE.md from its working directory, so an agent rooted at `/`
    // silently gets none.
    //
    // `BUZZ_HOST_WORKDIR` in the unit's env chooses it, so it can be set from
    // Buzz alongside every other agent setting. Falling back to the home
    // directory rather than leaving `/` — a missing directory is reported
    // rather than ignored, because silently working somewhere other than where
    // you were told to is how an agent edits the wrong copy of a file.
    let workdir = unit
        .env
        .get("BUZZ_HOST_WORKDIR")
        .cloned()
        .or_else(|| home().ok().map(|h| h.display().to_string()));
    if let Some(dir) = workdir {
        if Path::new(&dir).is_dir() {
            cmd.current_dir(&dir);
        } else {
            anyhow::bail!(
                "BUZZ_HOST_WORKDIR is {dir:?}, which is not a directory on this machine.\n\
                 Agent: {name}\n\
                 Create it, or unset it to start in the home directory."
            );
        }
    }

    // Pre-flight the harness itself.
    //
    // buzz-acp spawns its harness once per agent and, when the binary is not
    // there, reports `agent failed to spawn: No such file or directory` once
    // per agent and then `all N agents failed to start — cannot continue`.
    // Nothing in that names the command it tried, so it reads as buzz-acp
    // being broken. It is usually one of two ordinary things: the harness was
    // never installed on THIS machine, or it is installed somewhere the
    // supervisor's PATH does not reach.
    //
    // Both are worth distinguishing, and both are cheap to check here — before
    // launching a process that will fail ten times and exit.
    if let Some(spec) = unit.env.get("BUZZ_ACP_AGENT_COMMAND") {
        let bin = spec.split_whitespace().next().unwrap_or(spec);
        if !bin.is_empty() && resolve_on_path(bin, &path).is_none() {
            anyhow::bail!(
                "harness {bin:?} is not on this machine's PATH, so every agent would \
                 fail to spawn.\n\
                 Agent:    {name}\n\
                 Searched: {path}\n\
                 \n\
                 Either install it here, or point the agent at a harness that is \
                 present. An ACP harness has to exist on the machine that runs it — \
                 a containerised one (hive-acp) brings its own, a native one \
                 (claude-agent-acp, codex-acp) must be installed."
            );
        }
    }

    // Tell the agent what this machine calls it.
    //
    // Nothing downstream has a per-agent name otherwise: Buzz strips the
    // private key from the harness environment and `BUZZ_MANAGED_AGENT` is the
    // desktop INSTANCE id, shared by every agent it runs. A harness that wants
    // to keep per-agent state — hive naming a container, say — is left asking
    // the user to invent an identifier and set it by hand, and two agents that
    // are given the same one silently share everything.
    //
    // This costs nothing to publish and is the one identifier that is already
    // unique per agent on this machine.
    cmd.env("BUZZ_HOST_UNIT", name);

    for (k, v) in &unit.env {
        cmd.env(k, v);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        bail!("exec {program}: {err}");
    }
    #[cfg(not(unix))]
    {
        let status = cmd.status().with_context(|| format!("running {program}"))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Find `bin` on `path`, the way exec would.
///
/// An explicit path is checked as given; a bare name is searched. Executability
/// is checked rather than mere existence, because a non-executable file fails at
/// spawn with the same errno as a missing one.
fn resolve_on_path(bin: &str, path: &str) -> Option<PathBuf> {
    let executable = |p: &Path| {
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    if bin.contains('/') {
        let p = PathBuf::from(bin);
        return executable(&p).then_some(p);
    }
    path.split(':').filter(|d| !d.is_empty()).find_map(|d| {
        let p = Path::new(d).join(bin);
        executable(&p).then_some(p)
    })
}

/// The PATH a supervised agent gets: the conventional install prefixes, then
/// whatever the supervisor supplied.
///
/// Ordered most-specific first so a user's own `~/.local/bin` copy wins over a
/// system one — which is where harnesses installed by hand actually live.
fn default_path() -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Ok(home) = home() {
        parts.push(home.join(".local/bin").display().to_string());
        parts.push(home.join("bin").display().to_string());
    }
    for p in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        parts.push(p.to_string());
    }
    if let Ok(existing) = std::env::var("PATH") {
        for p in existing.split(':') {
            if !p.is_empty() && !parts.iter().any(|q| q == p) {
                parts.push(p.to_string());
            }
        }
    }
    parts.join(":")
}

fn remove(name: &str) -> Result<()> {
    check_name(name)?;
    supervisor().remove(name)?;
    let path = unit_file(name)?;
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    eprintln!("buzz-host: {name} removed (its log is kept)");
    Ok(())
}

fn list() -> Result<()> {
    let dir = state_dir()?;
    let mut names: Vec<String> = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let file = entry.file_name();
            let file = file.to_string_lossy();
            if let Some(stem) = file.strip_suffix(".json")
                && !file.starts_with('.')
            {
                names.push(stem.to_string());
            }
        }
    }
    names.sort();
    if names.is_empty() {
        println!("no agents installed");
        return Ok(());
    }
    println!("{:<24} {}", "NAME", "STATE");
    for n in names {
        let state = if supervisor().is_running(&n) { "running" } else { "stopped" };
        println!("{n:<24} {state}");
    }
    Ok(())
}

fn status(name: &str) -> Result<()> {
    check_name(name)?;
    if supervisor().is_running(name) {
        println!("{name}: running");
        Ok(())
    } else {
        println!("{name}: not running");
        std::process::exit(1);
    }
}

fn paths(name: Option<&str>) -> Result<()> {
    println!("state:     {}", state_dir()?.display());
    println!("buzz-host: {}", self_path()?.display());
    match find_buzz_acp() {
        Ok(p) => println!("buzz-acp:  {p}"),
        Err(e) => println!("buzz-acp:  NOT FOUND ({e})"),
    }
    if let Some(n) = name {
        check_name(n)?;
        println!("unit:      {}", unit_file(n)?.display());
        println!("log:       {}", log_file(n)?.display());
        println!("supervisor unit: {}", supervisor().unit_path(n)?.display());
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("securing {}", path.display()))?;
    }
    Ok(())
}

// ── supervisors ─────────────────────────────────────────────────────────────

trait Supervisor {
    /// Create or replace the unit and (re)start it. Returns its id.
    fn install(&self, name: &str, buzz_host: &Path) -> Result<String>;
    fn remove(&self, name: &str) -> Result<()>;
    fn is_running(&self, name: &str) -> bool;
    fn unit_path(&self, name: &str) -> Result<PathBuf>;
}

fn supervisor() -> Box<dyn Supervisor> {
    #[cfg(target_os = "macos")]
    {
        Box::new(Launchd)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(Systemd)
    }
}

// ── launchd ─────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
struct Launchd;

#[cfg(target_os = "macos")]
impl Launchd {
    fn domain() -> String {
        format!("gui/{}", unsafe { libc_getuid() })
    }
}

/// `getuid(2)` without a libc dependency for one call.
#[cfg(target_os = "macos")]
unsafe fn libc_getuid() -> u32 {
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() }
}

#[cfg(target_os = "macos")]
impl Supervisor for Launchd {
    fn unit_path(&self, name: &str) -> Result<PathBuf> {
        Ok(home()?.join("Library/LaunchAgents").join(format!("{}.plist", label(name))))
    }

    fn install(&self, name: &str, buzz_host: &Path) -> Result<String> {
        let label = label(name);
        let plist_path = self.unit_path(name)?;
        std::fs::create_dir_all(plist_path.parent().unwrap())?;
        let log = log_file(name)?;

        // KeepAlive so a crashed agent comes back, RunAtLoad so it starts
        // without waiting for a crash. ProcessType Background keeps macOS from
        // throttling a long-idle process the way it throttles Interactive ones.
        //
        // The plist contains NO environment: the key lives in the 0600 JSON,
        // and `buzz-host run` loads it. A plist is world-readable.
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{host}</string>
    <string>run</string>
    <string>{name}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
            host = xml_escape(&buzz_host.display().to_string()),
            log = xml_escape(&log.display().to_string()),
            name = xml_escape(name),
        );
        std::fs::write(&plist_path, plist)
            .with_context(|| format!("writing {}", plist_path.display()))?;

        let domain = Self::domain();
        // bootout first so a changed plist is actually re-read. `bootstrap`
        // against an already-loaded label fails, and reusing the old definition
        // is worse than failing: the agent keeps running with the previous
        // environment and the deploy looks successful.
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{label}")])
            .output();
        let out = Command::new("launchctl")
            .args(["bootstrap", &domain])
            .arg(&plist_path)
            .output()
            .context("launchctl bootstrap")?;
        if !out.status.success() {
            bail!(
                "launchctl bootstrap {}: {}",
                plist_path.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let _ = Command::new("launchctl")
            .args(["kickstart", "-k", &format!("{domain}/{label}")])
            .output();
        Ok(label)
    }

    fn remove(&self, name: &str) -> Result<()> {
        let label = label(name);
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{}/{}", Self::domain(), label)])
            .output();
        let p = self.unit_path(name)?;
        if p.exists() {
            std::fs::remove_file(&p).with_context(|| format!("removing {}", p.display()))?;
        }
        Ok(())
    }

    fn is_running(&self, name: &str) -> bool {
        // `launchctl print` exits non-zero when the label is not loaded; when
        // it is, "state = running" appears only while a process actually
        // exists. Checking the list alone would call a crash-looping agent
        // healthy.
        Command::new("launchctl")
            .args(["print", &format!("{}/{}", Self::domain(), label(name))])
            .output()
            .map(|o| {
                o.status.success() && String::from_utf8_lossy(&o.stdout).contains("state = running")
            })
            .unwrap_or(false)
    }
}

#[cfg(target_os = "macos")]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

// ── systemd ─────────────────────────────────────────────────────────────────

#[cfg(not(target_os = "macos"))]
struct Systemd;

#[cfg(not(target_os = "macos"))]
impl Systemd {
    fn unit_name(name: &str) -> String {
        format!("buzz-host-{name}.service")
    }
    fn systemctl(args: &[&str]) -> Result<std::process::Output> {
        Command::new("systemctl")
            .arg("--user")
            .args(args)
            .output()
            .context("running systemctl --user")
    }
}

#[cfg(not(target_os = "macos"))]
impl Supervisor for Systemd {
    fn unit_path(&self, name: &str) -> Result<PathBuf> {
        Ok(home()?.join(".config/systemd/user").join(Self::unit_name(name)))
    }

    fn install(&self, name: &str, buzz_host: &Path) -> Result<String> {
        let path = self.unit_path(name)?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        // No Environment= lines: the key lives in the 0600 JSON that
        // `buzz-host run` loads. Unit files are readable.
        let unit = format!(
            "[Unit]\n\
             Description=buzz agent {name}\n\
             After=network-online.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={host} run {name}\n\
             Restart=always\n\
             RestartSec=5\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
            host = buzz_host.display(),
        );
        std::fs::write(&path, unit).with_context(|| format!("writing {}", path.display()))?;

        Self::systemctl(&["daemon-reload"])?;
        let unit_name = Self::unit_name(name);
        let out = Self::systemctl(&["enable", "--now", &unit_name])?;
        if !out.status.success() {
            bail!(
                "systemctl --user enable --now {unit_name}: {}. If this is a headless host, \
                 `loginctl enable-linger $USER` is what keeps user units running after logout.",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        // enable --now does not restart an already-running unit, so a redeploy
        // would keep the previous environment.
        let _ = Self::systemctl(&["restart", &unit_name]);
        Ok(unit_name)
    }

    fn remove(&self, name: &str) -> Result<()> {
        let unit_name = Self::unit_name(name);
        let _ = Self::systemctl(&["disable", "--now", &unit_name]);
        let p = self.unit_path(name)?;
        if p.exists() {
            std::fs::remove_file(&p).with_context(|| format!("removing {}", p.display()))?;
        }
        let _ = Self::systemctl(&["daemon-reload"]);
        Ok(())
    }

    fn is_running(&self, name: &str) -> bool {
        Self::systemctl(&["is-active", "--quiet", &Self::unit_name(name)])
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_bare_name_is_found_on_path_and_a_missing_one_is_not() {
        // The check that turns "all 10 agents failed to start" into a sentence
        // naming the harness. `sh` is on every PATH this runs on.
        assert!(resolve_on_path("sh", "/nonexistent:/bin:/usr/bin").is_some());
        assert!(resolve_on_path("definitely-not-a-harness", "/bin:/usr/bin").is_none());
    }

    #[test]
    fn an_explicit_path_is_used_as_given_rather_than_searched() {
        assert!(resolve_on_path("/bin/sh", "/nowhere").is_some());
        assert!(resolve_on_path("/bin/definitely-not-here", "/bin").is_none());
    }

    #[test]
    fn a_file_that_is_present_but_not_executable_counts_as_missing() {
        // It fails at spawn with the same errno as an absent one, so reporting
        // it as present would send the reader looking in the wrong place.
        let dir = std::env::temp_dir().join(format!("buzz-host-t{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("harness");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(resolve_on_path("harness", dir.to_str().unwrap()).is_none());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(resolve_on_path("harness", dir.to_str().unwrap()).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_injected_path_reaches_where_harnesses_are_actually_installed() {
        // A native adapter installed by npm lands in the brew prefix, and one
        // installed by hand lands in ~/.local/bin. Both were real cases.
        let p = default_path();
        assert!(p.contains("/opt/homebrew/bin"), "{p}");
        assert!(p.contains(".local/bin"), "{p}");
    }
    use super::*;

    #[test]
    fn a_name_that_could_escape_the_state_directory_is_refused() {
        // It becomes a filename and a unit label. `../` in either is the whole
        // problem.
        for bad in ["", "../etc/passwd", "a/b", "Agent", "has space", "sem;colon"] {
            assert!(check_name(bad).is_err(), "accepted {bad:?}");
        }
        for good in ["research", "uni-2", "a_b", "x9"] {
            assert!(check_name(good).is_ok(), "refused {good:?}");
        }
    }

    #[test]
    fn a_unit_round_trips_through_json() {
        let mut env = BTreeMap::new();
        env.insert("BUZZ_RELAY_URL".to_string(), "wss://example".to_string());
        let u = AgentUnit {
            program: Some("/usr/local/bin/buzz-acp".into()),
            args: vec![],
            env,
        };
        let s = serde_json::to_string(&u).unwrap();
        let back: AgentUnit = serde_json::from_str(&s).unwrap();
        assert_eq!(back.program.as_deref(), Some("/usr/local/bin/buzz-acp"));
        assert_eq!(back.env.get("BUZZ_RELAY_URL").unwrap(), "wss://example");
    }

    #[test]
    fn a_description_with_no_program_is_valid_and_resolved_later() {
        // The provider cannot know where buzz-acp lives on a host it has never
        // seen, so omitting it is the normal case rather than an error.
        let u: AgentUnit = serde_json::from_str(r#"{"env":{}}"#).unwrap();
        assert!(u.program.is_none());
        assert!(u.args.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_plist_escapes_a_path_that_would_break_the_xml() {
        assert_eq!(xml_escape("/a & b/<c>"), "/a &amp; b/&lt;c&gt;");
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn the_agent_path_leads_with_the_conventional_install_prefixes() {
        // launchd gives a job /usr/bin:/bin:/usr/sbin:/sbin, so a harness in
        // ~/.local/bin is invisible and buzz-acp reports "No such file or
        // directory" for a binary that is plainly installed.
        let p = default_path();
        let parts: Vec<&str> = p.split(':').collect();
        assert!(parts.iter().any(|d| d.ends_with("/.local/bin")), "{p}");
        assert!(parts.contains(&"/opt/homebrew/bin"), "{p}");
        assert!(parts.contains(&"/usr/bin"), "{p}");

        let local = parts.iter().position(|d| d.ends_with("/.local/bin")).unwrap();
        let usr = parts.iter().position(|d| *d == "/usr/bin").unwrap();
        assert!(local < usr, "a hand-installed harness must win over a system one: {p}");
    }

    #[test]
    fn the_path_has_no_duplicates() {
        // The inherited PATH overlaps the defaults; repeating entries makes
        // `buzz-host paths` output unreadable at exactly the moment someone is
        // using it to work out why a binary was not found.
        let p = default_path();
        let parts: Vec<&str> = p.split(':').collect();
        let mut uniq = parts.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(parts.len(), uniq.len(), "{p}");
    }
}
