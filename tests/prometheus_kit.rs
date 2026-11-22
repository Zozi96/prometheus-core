use prometheus_core::hook::REREAD_DENIAL_MESSAGE;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_prometheus-kit")
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("prom_kit_it_{tag}_{}_{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn write(&self, rel: &str, content: &[u8]) -> PathBuf {
        let p = self.0.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, content).unwrap();
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_kit(args: &[&str], cwd: Option<&Path>) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .env("PROMETHEUS_KIT_NO_METRICS", "1");
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.output().expect("failed to execute prometheus-kit")
}

#[test]
fn help_and_version_exit_zero() {
    let ver = run_kit(&["--version"], None);
    assert_eq!(ver.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&ver.stdout).starts_with("prometheus-kit "));

    for args in [
        &["--help"][..],
        &["outline", "--help"][..],
        &["slice", "--help"][..],
        &["compact", "--help"][..],
        &["search", "--help"][..],
        &["diff", "--help"][..],
        &["map", "--help"][..],
        &["hook", "--help"][..],
        &["droid-mode", "--help"][..],
    ] {
        let out = run_kit(args, None);
        assert_eq!(out.status.code(), Some(0), "args={args:?}");
        assert!(!out.stdout.is_empty());
    }
}

#[test]
fn outline_supports_all_formats_filters_and_json_budget() {
    let tmp = TempDir::new("outline_all");
    let cs = tmp.write(
        "Service.cs",
        br#"using System;
namespace Demo.App;
public class Worker
{
    private int _secret;
    [Fact]
    public void Run() { }
    public int Value => 42;
}
"#,
    );
    let md = tmp.write(
        "Doc.md",
        b"# Root\nIntro\n```sh\n# ignored heading\n```\n## Details\nText\n",
    );
    let json = tmp.write(
        "cfg.json",
        b"{\n  \"alpha\": {\"nested\": {\"deep\": 1}},\n  \"beta\": [{\"id\": 1, \"ok\": true}]\n}\n",
    );

    // Multi-file outline
    let out = run_kit(
        &[
            "outline",
            "--imports",
            cs.to_str().unwrap(),
            md.to_str().unwrap(),
            json.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(0));
    let txt = String::from_utf8_lossy(&out.stdout);
    assert!(txt.contains("imports: using System"));
    assert!(txt.contains("namespace Demo.App"));
    assert!(txt.contains("[Fact] public void Run()"));
    assert!(!txt.contains("_secret"));
    assert!(txt.contains("## Details"));
    assert!(!txt.contains("ignored heading"));
    assert!(txt.contains("sample={id, ok}"));

    // --all reveals private fields; --kind filters cleanly
    let out_all = run_kit(&["outline", "--all", "--kind", "field", cs.to_str().unwrap()], None);
    assert_eq!(out_all.status.code(), Some(0));
    let txt_all = String::from_utf8_lossy(&out_all.stdout);
    assert!(txt_all.contains("_secret"));
    assert!(!txt_all.contains("Run()"));

    // --filter narrows cleanly
    let out_flt = run_kit(&["outline", "--filter", "deep", json.to_str().unwrap()], None);
    assert_eq!(out_flt.status.code(), Some(0));
    let txt_flt = String::from_utf8_lossy(&out_flt.stdout);
    assert!(txt_flt.contains("deep: 1"));
    assert!(!txt_flt.contains("beta"));

    // --json + tight --max-tokens reports truncation metadata
    let many_items: String = (0..60)
        .map(|i| format!("pub fn func_number_{i}(arg: usize) -> usize {{ {i} }}\n"))
        .collect();
    let rs = tmp.write("many.rs", many_items.as_bytes());
    let json_out = run_kit(
        &["outline", "--json", "--max-tokens", "200", rs.to_str().unwrap()],
        None,
    );
    assert_eq!(json_out.status.code(), Some(0));
    assert!(
        json_out.stdout.len() <= 200 * 4 + 2,
        "outline json exceeded budget: {} bytes",
        json_out.stdout.len()
    );
    let parsed: Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert_eq!(parsed["truncated"], Value::Bool(true));
    assert!(parsed["omitted_items"].as_u64().unwrap() > 0);

    let slice_spec = format!("{}:1-60", rs.display());
    let slice_json = run_kit(
        &["slice", "--json", "--max-tokens", "150", &slice_spec],
        None,
    );
    assert_eq!(slice_json.status.code(), Some(0));
    assert!(
        slice_json.stdout.len() <= 150 * 4 + 2,
        "slice json exceeded budget: {} bytes",
        slice_json.stdout.len()
    );
    let parsed_slice: Value = serde_json::from_slice(&slice_json.stdout).unwrap();
    assert_eq!(parsed_slice["truncated"], Value::Bool(true));

    // Text budget truncation marker
    let txt_budget = run_kit(&["outline", "--max-tokens", "80", rs.to_str().unwrap()], None);
    assert_eq!(txt_budget.status.code(), Some(0));
    let s = String::from_utf8_lossy(&txt_budget.stdout);
    assert!(s.contains("omitted items; narrow with --depth, --filter, or --max-tokens"));
}

#[test]
fn slice_end_to_end_across_code_structured_and_batch() {
    let tmp = TempDir::new("slice_all");
    let rs = tmp.write(
        "lib.rs",
        b"pub struct Bag {\n    x: i32,\n}\nimpl Bag {\n    pub fn get(&self) -> i32 {\n        self.x\n    }\n}\n",
    );
    let jsonc = tmp.write(
        "data.jsonc",
        b"{\n  // c\n  \"a/b\": [\n    {\"k\": \"v0\"},\n    {\n      \"k\": \"v1\"\n    }\n  ]\n}\n",
    );
    let jsonl = tmp.write(
        "events.jsonl",
        b"{\"type\":\"open\",\"id\":1}\n{\"type\":\"err\",\"msg\":\"boom\"}\n{\"type\":\"done\",\"id\":2}\n",
    );
    let yaml = tmp.write(
        "wf.yml",
        b"jobs:\n  test:\n    steps:\n      - run: |\n          echo hi\n      - run: echo ok\n",
    );
    let toml = tmp.write("cfg.toml", b"[package]\nname = \"x\"\n\n[profile.release]\nlto = true\n");
    let md = tmp.write("notes.md", b"# Guide\nIntro\n## Quick Start\nStep 1\n");

    let spec_rs = format!("{}::Bag::get", rs.display());
    let spec_json = format!("{}::/a~1b/1/k", jsonc.display());
    let spec_jsonl = format!("{}::type=err", jsonl.display());
    let spec_yaml = format!("{}::jobs.test.steps[0].run", yaml.display());
    let spec_toml = format!("{}::profile.release", toml.display());
    let spec_md = format!("{}::quick-start", md.display());

    let out = run_kit(
        &[
            "slice",
            "--json",
            &spec_rs,
            &spec_json,
            &spec_jsonl,
            &spec_yaml,
            &spec_toml,
            &spec_md,
        ],
        None,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let slices = v["slices"].as_array().unwrap();
    assert_eq!(slices.len(), 6);
    assert_eq!(slices[0]["start_line"], 5);
    assert_eq!(slices[1]["start_line"], 6);
    assert_eq!(slices[1]["lines"][0]["text"], "      \"k\": \"v1\"");
    assert_eq!(slices[2]["lines"][0]["line"], 2);
    assert_eq!(slices[3]["start_line"], 4);
    assert_eq!(slices[4]["start_line"], 4);
    assert_eq!(slices[5]["start_line"], 3);

    // Signatures-only mode & context merging
    let sig_out = run_kit(&["slice", "--signatures-only", &spec_rs], None);
    assert_eq!(sig_out.status.code(), Some(0));
    let sig_txt = String::from_utf8_lossy(&sig_out.stdout);
    assert!(sig_txt.contains("L5-L7 pub fn get(&self) -> i32"));

    // Multi-range batching + context + --no-line-numbers
    let range_spec = format!("{}:1,3-4", rs.display());
    let r_out = run_kit(&["slice", "-C", "1", "--no-line-numbers", &range_spec], None);
    assert_eq!(r_out.status.code(), Some(0));
    let r_txt = String::from_utf8_lossy(&r_out.stdout);
    assert!(r_txt.contains("L1-L5 ==="));
    assert!(!r_txt.contains("L1: "));
}

#[test]
fn error_exit_codes_are_deterministic() {
    let tmp = TempDir::new("errs");
    let bin_file = tmp.write("raw.bin", b"\x00\x01\x02");
    let cs_file = tmp.write("A.cs", b"public class Alpha { public void Ping() {} }\n");

    // Exit 2 on usage errors
    assert_eq!(run_kit(&[], None).status.code(), Some(2));
    assert_eq!(run_kit(&["unknown"], None).status.code(), Some(2));
    assert_eq!(run_kit(&["outline"], None).status.code(), Some(2));
    assert_eq!(run_kit(&["slice", cs_file.to_str().unwrap()], None).status.code(), Some(2));
    assert_eq!(
        run_kit(&["slice", &format!("{}:9-2", cs_file.display())], None)
            .status
            .code(),
        Some(2)
    );

    // Exit 1 on missing/binary/missing-symbol errors
    assert_eq!(
        run_kit(&["outline", tmp.0.join("missing.rs").to_str().unwrap()], None)
            .status
            .code(),
        Some(1)
    );
    assert_eq!(
        run_kit(&["outline", "--lang", "rust", bin_file.to_str().unwrap()], None)
            .status
            .code(),
        Some(1)
    );
    let miss_sym = run_kit(
        &["slice", &format!("{}::Png", cs_file.display())],
        None,
    );
    assert_eq!(miss_sym.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&miss_sym.stderr).contains("Alpha.Ping"));
}

#[test]
fn compact_search_diff_and_map_end_to_end() {
    use std::io::Write as _;
    use std::process::Stdio;

    let tmp = TempDir::new("kit4");
    let log_file = tmp.write(
        "build.log",
        b"  Determining projects to restore...\n\
src/A.cs(10,2): error CS0103: missing Foo [/tmp/A.csproj]\n\
src/B.cs(20,4): error CS0103: missing Foo [/tmp/A.csproj]\n",
    );

    // 1. compact: file input + JSON budget + command exit-code preservation + stdin
    let cmp_file = run_kit(
        &["compact", "--no-spillover", "--json", "--max-tokens", "200", log_file.to_str().unwrap()],
        None,
    );
    assert_eq!(cmp_file.status.code(), Some(0));
    assert!(cmp_file.stdout.len() <= 200 * 4 + 2);
    let cmp_json: Value = serde_json::from_slice(&cmp_file.stdout).unwrap();
    assert_eq!(cmp_json["diagnostics"][0]["count"], 2);

    let cmp_cmd = run_kit(
        &["compact", "--no-spillover", "--", "sh", "-c", "echo hi; exit 5"],
        None,
    );
    assert_eq!(cmp_cmd.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&cmp_cmd.stdout).contains("exit 5"));

    let mut child = Command::new(bin())
        .args(["compact", "--no-spillover", "--tail", "5"])
        .env("PROMETHEUS_KIT_NO_METRICS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"line1\nline2\nline2\nline2\n")
        .unwrap();
    let stdin_out = child.wait_with_output().unwrap();
    assert_eq!(stdin_out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&stdin_out.stdout).contains("line2 (x3)"));

    // 2. search: symbols, noise skip, minified clipping, JSON budget, invalid regex -> exit 2
    tmp.write(
        "src/svc.rs",
        b"pub struct Svc;\nimpl Svc {\n    pub fn run_job(&self) {\n        let token_hit = 1;\n    }\n}\n",
    );
    tmp.write("Cargo.lock", b"token_hit = 1\n");
    let srch = run_kit(
        &[
            "search",
            "--symbols",
            "--json",
            "--max-tokens",
            "300",
            "token_hit",
            tmp.0.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(srch.status.code(), Some(0));
    assert!(srch.stdout.len() <= 300 * 4 + 2);
    let srch_v: Value = serde_json::from_slice(&srch.stdout).unwrap();
    assert_eq!(srch_v["total_files"], 1);
    assert_eq!(
        srch_v["files"][0]["matches"][0]["symbol"],
        Value::String("Svc::run_job".to_owned())
    );
    assert_eq!(
        run_kit(&["search", "[bad", tmp.0.to_str().unwrap()], None)
            .status
            .code(),
        Some(2)
    );

    // 3. map: depth, symbols, JSON budget
    let mp = run_kit(
        &[
            "map",
            "--symbols",
            "--json",
            "--max-tokens",
            "300",
            tmp.0.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(mp.status.code(), Some(0));
    assert!(mp.stdout.len() <= 300 * 4 + 2);
    let mp_v: Value = serde_json::from_slice(&mp.stdout).unwrap();
    assert!(mp_v["total_files"].as_u64().unwrap() >= 2);

    // 4. diff: init git repo in tmp, commit, edit, run --status, worktree --symbol, --stat, and JSON budget
    let git = |args: &[&str]| {
        let st = Command::new("git")
            .arg("-C")
            .arg(&tmp.0)
            .args(args)
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?} failed");
    };
    git(&["init"]);
    git(&["config", "user.email", "t@example.com"]);
    git(&["config", "user.name", "Test"]);
    git(&["add", "-A"]);
    git(&["commit", "-m", "init"]);

    tmp.write(
        "src/svc.rs",
        b"pub struct Svc;\nimpl Svc {\n    pub fn run_job(&self) {\n        let token_hit = 99;\n    }\n}\n",
    );
    tmp.write("Cargo.lock", b"token_hit = 2\n");

    let st_out = run_kit(&["diff", "--root", tmp.0.to_str().unwrap(), "--status"], None);
    assert_eq!(st_out.status.code(), Some(0));
    let st_txt = String::from_utf8_lossy(&st_out.stdout);
    assert!(st_txt.contains("src/svc.rs"));
    assert!(st_txt.contains("excluded noise (1): Cargo.lock"));

    let df_out = run_kit(
        &[
            "diff",
            "--root",
            tmp.0.to_str().unwrap(),
            "--symbol",
            "run_job",
            "--json",
            "--max-tokens",
            "350",
        ],
        None,
    );
    assert_eq!(df_out.status.code(), Some(0));
    assert!(df_out.stdout.len() <= 350 * 4 + 2);
    let df_v: Value = serde_json::from_slice(&df_out.stdout).unwrap();
    assert_eq!(df_v["files"][0]["path"], "src/svc.rs");
}

fn run_kit_stdin(args: &[&str], stdin_bytes: &[u8]) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(bin())
        .args(args)
        .env("PROMETHEUS_KIT_NO_METRICS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn prometheus-kit");
    child.stdin.as_mut().unwrap().write_all(stdin_bytes).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn hook_subcommand_handles_all_five_hosts() {
    let tmp = TempDir::new("hook_cli");
    let repo = tmp.0.join("repo");
    fs::create_dir_all(&repo).unwrap();
    let sample = repo.join("hello.rs");
    fs::write(&sample, "fn main() {}\n").unwrap();

    for host in ["claude", "droid", "devin", "muse"] {
        let ev = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": ".env"},
            "cwd": repo,
            "session_id": format!("sess-{host}"),
        });
        let out = run_kit_stdin(&["hook", host], ev.to_string().as_bytes());
        assert_eq!(out.status.code(), Some(0), "host={host}");
        let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            "ask",
            parsed["hookSpecificOutput"]["permissionDecision"],
            "host={host}"
        );
    }

    let cursor_ev = serde_json::json!({
        "hook_event_name": "preToolUse",
        "tool_name": "Read",
        "tool_input": {"path": ".env"},
        "workspace_roots": [repo],
        "conversation_id": "sess-cursor",
    });
    let cursor_out = run_kit_stdin(&["hook", "cursor"], cursor_ev.to_string().as_bytes());
    assert_eq!(cursor_out.status.code(), Some(0));
    let cursor_parsed: Value = serde_json::from_slice(&cursor_out.stdout).unwrap();
    assert_eq!("deny", cursor_parsed["permission"]);

    // Antigravity (#87): secret ask, and pass paths never emit `{}`.
    let agy_ev = serde_json::json!({
        "hookEventName": "PreToolUse",
        "conversationId": "sess-antigravity",
        "workspacePaths": [repo],
        "cwd": repo,
        "lastUserInput": "",
        "toolCall": {"name": "view_file", "args": {"AbsolutePath": ".env"}},
    });
    let agy_out = run_kit_stdin(&["hook", "antigravity"], agy_ev.to_string().as_bytes());
    assert_eq!(agy_out.status.code(), Some(0));
    let agy_parsed: Value = serde_json::from_slice(&agy_out.stdout).unwrap();
    assert_eq!("ask", agy_parsed["decision"]);
    let agy_pass = serde_json::json!({
        "hookEventName": "PreToolUse",
        "conversationId": "sess-antigravity",
        "workspacePaths": [repo],
        "cwd": repo,
        "lastUserInput": "",
        "toolCall": {"name": "run_command", "args": {"CommandLine": "echo hi"}},
    });
    let agy_pass_out = run_kit_stdin(&["hook", "antigravity"], agy_pass.to_string().as_bytes());
    let agy_pass_parsed: Value = serde_json::from_slice(&agy_pass_out.stdout).unwrap();
    assert_eq!(
        serde_json::json!({"decision": "allow"}),
        agy_pass_parsed,
        "antigravity pass must never emit {{}}"
    );

    // Grok (#88): secret deny; pass is `{}`.
    let grok_ev = serde_json::json!({
        "hookEventName": "PreToolUse",
        "sessionId": "sess-grok",
        "cwd": repo,
        "workspaceRoot": repo,
        "toolName": "read_file",
        "toolInput": {"file_path": ".env"},
    });
    let grok_out = run_kit_stdin(&["hook", "grok"], grok_ev.to_string().as_bytes());
    assert_eq!(grok_out.status.code(), Some(0));
    let grok_parsed: Value = serde_json::from_slice(&grok_out.stdout).unwrap();
    assert_eq!("deny", grok_parsed["decision"]);

    // Invalid host exits 2.
    let bad = run_kit(&["hook", "bogus"], None);
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn droid_mode_subcommand_round_trips_with_config_and_home() {
    let tmp = TempDir::new("droid_cli");
    let cfg = tmp.write(
        "droid-modes.json",
        br#"{
  "off": {
    "droids": {"argus": ["gemini-4-carbon", "medium"]},
    "session": {"model": "gpt-6.2-sol", "reasoningEffort": "medium"},
    "subagents": {"lightModel": "deepseek-v4.1-flash-1017", "lightReasoningEffort": "low"}
  },
  "on": {
    "droids": {"argus": ["glm-5.3", "high"]},
    "session": {"model": "kimi-k3.1-pro", "reasoningEffort": "medium"},
    "subagents": {"lightModel": "deepseek-v4.1-flash-1017", "lightReasoningEffort": "low"}
  }
}"#,
    );
    let argus = tmp.write(
        ".factory/droids/argus.md",
        b"---\nname: argus\nmodel: gemini-4-carbon\nreasoningEffort: medium\n---\nReview body.\n",
    );
    let on = run_kit(
        &[
            "droid-mode",
            "on",
            "--config",
            cfg.to_str().unwrap(),
            "--home",
            tmp.0.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(on.status.code(), Some(0), "{}", String::from_utf8_lossy(&on.stderr));
    let on_out = String::from_utf8_lossy(&on.stdout);
    assert!(on_out.contains("/model kimi-k3.1-pro"));
    let updated = fs::read_to_string(&argus).unwrap();
    assert!(updated.contains("model: glm-5.3\nreasoningEffort: high\n"));

    let off = run_kit(
        &[
            "droid-mode",
            "off",
            "--config",
            cfg.to_str().unwrap(),
            "--home",
            tmp.0.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(off.status.code(), Some(0));
    let restored = fs::read_to_string(&argus).unwrap();
    assert!(restored.contains("model: gemini-4-carbon\nreasoningEffort: medium\n"));
}

// ---------------------------------------------------------------------------
// Metrics persistence: every test gets a child-only HOME/USERPROFILE and
// XDG_RUNTIME_DIR inside a fresh temp dir, so savings.jsonl never lands in a
// real home.
// ---------------------------------------------------------------------------

const REWRITE_COMMAND: &str = "dotnet test App.csproj";
const METRICS_MAX_BYTES: usize = 1024 * 1024;

struct MetricsHome {
    _root: TempDir,
    home: PathBuf,
    runtime: PathBuf,
    repo: PathBuf,
}

impl MetricsHome {
    fn new(tag: &str) -> Self {
        let root = TempDir::new(tag);
        let home = root.0.join("home");
        let runtime = root.0.join("runtime");
        let repo = root.0.join("repo");
        fs::create_dir_all(&home).unwrap();
        // Elevated Windows runners create objects owned by the Administrators
        // group rather than the token user, which the private-route owner
        // check refuses. Re-own only this disposable fixture home.
        #[cfg(windows)]
        {
            let out = Command::new("whoami")
                .args(["/user", "/fo", "csv", "/nh"])
                .output()
                .unwrap();
            assert!(out.status.success());
            let text = String::from_utf8_lossy(&out.stdout);
            let sid = text.trim().rsplit(',').next().unwrap().trim_matches('"');
            assert!(sid.starts_with("S-1-"));
            let out = Command::new("icacls")
                .arg(&home)
                .arg("/setowner")
                .arg(format!("*{sid}"))
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "icacls /setowner on temporary HOME: {out:?}"
            );
        }
        fs::create_dir_all(&runtime).unwrap();
        fs::create_dir_all(&repo).unwrap();
        // umask 0002 leaves these 0775; the POSIX ancestor walk for private
        // logs refuses group-writable dirs, so pin the fixture dirs owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for dir in [&root.0, &home, &runtime, &repo] {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        Self {
            _root: root,
            home,
            runtime,
            repo,
        }
    }

    fn metrics_file(&self) -> PathBuf {
        self.home.join(".agents/prometheus/metrics/savings.jsonl")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(bin());
        cmd.args(args)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env_remove("PROMETHEUS_KIT_NO_METRICS")
            .env_remove("PROMETHEUS_KIT_NO_REWRITE")
            .env_remove("PROMETHEUS_KIT_NO_READ_HINT")
            .env_remove("PROMETHEUS_KIT_RTK_COEXIST")
            .env_remove("CURSOR_PROJECT_DIR")
            .env_remove("DEVIN_PROJECT_DIR")
            .env_remove("CLAUDECODE")
            .env_remove("FACTORY_DROID_SESSION_ID")
            .env_remove("MUSE_SESSION_ID")
            .env_remove("GROK_SESSION_ID")
            .env_remove("ANTIGRAVITY_CONVERSATION_ID");
        cmd
    }

    fn hook_env(&self, host: &str, event: &Value, extra: &[(&str, &str)]) -> Output {
        use std::io::Write;
        use std::process::Stdio;
        let mut cmd = self.command(&["hook", host]);
        for (key, value) in extra {
            cmd.env(key, value);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn prometheus-kit hook");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(event.to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn hook(&self, host: &str, event: &Value) -> Output {
        self.hook_env(host, event, &[])
    }

    fn metrics(&self) -> Output {
        self.command(&["metrics"])
            .output()
            .expect("failed to run prometheus-kit metrics")
    }

    fn rows(&self) -> Vec<Value> {
        let file = self.metrics_file();
        let text = fs::read_to_string(&file).unwrap_or_else(|err| {
            let probe = |p: &Path| {
                if p.exists() {
                    "exists"
                } else {
                    "missing"
                }
            };
            panic!(
                "metrics store unreadable at {}: {err}; .agents={}, .agents/prometheus={}, metrics={}, file={}",
                file.display(),
                probe(&self.home.join(".agents")),
                probe(&self.home.join(".agents").join("prometheus")),
                probe(&self.home.join(".agents").join("prometheus").join("metrics")),
                probe(&file),
            )
        });
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn rewrite_event(tool: &str, cwd: &Path, session: &str) -> Value {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": REWRITE_COMMAND},
        "cwd": cwd.to_str().unwrap(),
        "session_id": session,
    })
}

fn read_event(host: &str, cwd: &Path, file: &str) -> Value {
    let session = format!("sess-{host}");
    match host {
        "cursor" => serde_json::json!({
            "hook_event_name": "preToolUse",
            "tool_name": "Read",
            "tool_input": {"path": file},
            "workspace_roots": [cwd.to_str().unwrap()],
            "conversation_id": session,
        }),
        "devin" => serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "read",
            "tool_input": {"file_path": file},
            "cwd": cwd.to_str().unwrap(),
            "session_id": session,
        }),
        _ => serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": file},
            "cwd": cwd.to_str().unwrap(),
            "session_id": session,
        }),
    }
}

fn find_row<'a>(rows: &'a [Value], host: &str, rule: &str) -> &'a Value {
    rows.iter()
        .find(|row| row["host"].as_str() == Some(host) && row["rule_id"].as_str() == Some(rule))
        .unwrap_or_else(|| panic!("missing metrics row for {host}/{rule}"))
}

fn assert_metric_row_keys(row: &Value) {
    let obj = row.as_object().expect("metric row must be an object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["emitted_bytes", "host", "raw_bytes", "rule_id", "timestamp"],
        "unexpected metric row keys: {row}"
    );
}

#[test]
fn metrics_records_shell_rewrite_for_rewrite_hosts() {
    let home = MetricsHome::new("rewrite_metrics");
    for (host, tool) in [
        ("claude", "Bash"),
        ("devin", "exec"),
        ("droid", "Execute"),
        ("muse", "Bash"),
    ] {
        let ev = rewrite_event(tool, &home.repo, &format!("sess-{host}"));
        let out = home.hook(host, &ev);
        assert_eq!(out.status.code(), Some(0), "host={host}");
        let reply: Value = serde_json::from_slice(&out.stdout).unwrap();
        let command = reply["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .expect("rewrite reply carries updatedInput.command");
        assert!(
            command.contains("compact --mode test"),
            "host={host}: {command}"
        );
    }
    let cursor_ev = serde_json::json!({
        "hook_event_name": "preToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": REWRITE_COMMAND, "working_directory": home.repo.to_str().unwrap()},
        "workspace_roots": [home.repo.to_str().unwrap()],
        "conversation_id": "sess-cursor",
    });
    let c_out = home.hook("cursor", &cursor_ev);
    assert_eq!(c_out.status.code(), Some(0));
    let c_reply: Value = serde_json::from_slice(&c_out.stdout).unwrap();
    assert_eq!("allow", c_reply["permission"]);
    assert!(c_reply["updated_input"]["command"]
        .as_str()
        .unwrap()
        .contains("compact --mode test"));

    let rows = home.rows();
    assert_eq!(rows.len(), 5, "rows: {rows:?}");
    for host in ["claude", "cursor", "devin", "droid", "muse"] {
        let row = find_row(&rows, host, "shell-rewrite");
        assert_metric_row_keys(row);
        assert_eq!(
            row["raw_bytes"].as_u64().unwrap(),
            REWRITE_COMMAND.len() as u64
        );
        assert!(row["emitted_bytes"].as_u64().unwrap() > 0);
        assert!(row["timestamp"].as_u64().unwrap() > 0);
    }

    let totals = home.metrics();
    assert_eq!(totals.status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&totals.stdout).unwrap();
    assert_eq!(parsed["by_rule"]["shell-rewrite"]["count"], 5);
    for host in ["claude", "cursor", "devin", "droid", "muse"] {
        assert_eq!(parsed["by_host"][host]["count"], 1, "host={host}");
    }
}

#[test]
fn metrics_records_read_denials_for_all_hosts() {
    let home = MetricsHome::new("deny_metrics");
    let mut big = String::new();
    for i in 0..250 {
        big.push_str(&format!("fn func_{i}() {{}}\n"));
    }
    fs::write(home.repo.join("big.rs"), &big).unwrap();
    let big_bytes = big.len() as u64;
    fs::write(home.repo.join("small.rs"), "fn s() {}\n".repeat(10)).unwrap();

    for host in ["claude", "cursor", "devin", "droid", "muse"] {
        let ev = read_event(host, &home.repo, "big.rs");
        // 4-state cycle: first-read-denial -> allowed-retry -> reread-denial -> allowed-retry.
        for _ in 0..4 {
            let out = home.hook(host, &ev);
            assert_eq!(out.status.code(), Some(0), "host={host}");
        }
        let small = read_event(host, &home.repo, "small.rs");
        for _ in 0..2 {
            let out = home.hook(host, &small);
            assert_eq!(out.status.code(), Some(0), "host={host}");
        }
        if host == "claude" {
            // An identical range on the same large file passes on first read,
            // denies once on reread, and allows retry with proportional estimate.
            let range_ev = serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "big.rs", "offset": 0, "limit": 50},
                "cwd": home.repo.to_str().unwrap(),
                "session_id": "sess-claude",
            });
            for _ in 0..3 {
                let out = home.hook(host, &range_ev);
                assert_eq!(out.status.code(), Some(0), "host={host}");
            }
        }
    }

    let rows = home.rows();
    // Per host (4 calls on big.rs): first-read-denial + allowed-retry + reread-denial + allowed-retry = 4 rows.
    // Small.rs reread warns ONLY on context-delivering hosts (claude, muse) = +2 rows (zero phantom metrics on cursor/devin/droid).
    // Claude range reads add reread-denial + allowed-retry = +2 rows. Total = 5*4 + 2 + 2 = 24.
    assert_eq!(rows.len(), 24, "rows: {rows:?}");
    for row in &rows {
        assert_metric_row_keys(row);
    }
    let range_estimate = (big_bytes as u128 * 50 / 250) as u64;
    for host in ["claude", "cursor", "devin", "droid", "muse"] {
        let first_denial = find_row(&rows, host, "first-read-denial");
        assert_eq!(first_denial["raw_bytes"].as_u64().unwrap(), big_bytes);
        assert!(first_denial["emitted_bytes"].as_u64().unwrap() > 0);

        let denial = find_row(&rows, host, "reread-denial");
        assert_eq!(denial["raw_bytes"].as_u64().unwrap(), big_bytes);
        assert_eq!(
            denial["emitted_bytes"].as_u64().unwrap(),
            REREAD_DENIAL_MESSAGE.len() as u64
        );

        let whole_retries: Vec<&Value> = rows
            .iter()
            .filter(|r| {
                r["host"].as_str() == Some(host)
                    && r["rule_id"].as_str() == Some("allowed-retry")
                    && r["emitted_bytes"].as_u64() == Some(big_bytes)
            })
            .collect();
        assert_eq!(whole_retries.len(), 2, "host={host} whole retries: {whole_retries:?}");
        for retry in whole_retries {
            assert_eq!(retry["raw_bytes"].as_u64().unwrap(), 0);
        }

        let has_warning = rows
            .iter()
            .any(|r| r["host"].as_str() == Some(host) && r["rule_id"].as_str() == Some("reread-warning"));
        if matches!(host, "claude" | "muse") {
            assert!(has_warning, "expected reread-warning for {host}");
        } else {
            assert!(!has_warning, "phantom reread-warning recorded for {host}");
        }
    }

    // No phantom large-read-advisory rows are ever emitted.
    assert!(
        !rows.iter().any(|r| r["rule_id"].as_str() == Some("large-read-advisory")),
        "unexpected large-read-advisory row: {rows:?}"
    );

    // Claude's range reads produced their own denial/retry pair with the
    // proportional byte estimate.
    let range_denial = rows
        .iter()
        .find(|row| {
            row["host"].as_str() == Some("claude")
                && row["rule_id"].as_str() == Some("reread-denial")
                && row["raw_bytes"].as_u64() == Some(range_estimate)
        })
        .expect("missing range reread-denial row");
    assert_eq!(
        range_denial["emitted_bytes"].as_u64().unwrap(),
        REREAD_DENIAL_MESSAGE.len() as u64
    );
    let range_retry = rows
        .iter()
        .find(|row| {
            row["host"].as_str() == Some("claude")
                && row["rule_id"].as_str() == Some("allowed-retry")
                && row["emitted_bytes"].as_u64() == Some(range_estimate)
        })
        .expect("missing range allowed-retry row");
    assert_eq!(range_retry["raw_bytes"].as_u64().unwrap(), 0);
}

#[test]
fn metrics_opt_out_disables_writes() {
    let home = MetricsHome::new("optout_metrics");
    let ev = rewrite_event("Bash", &home.repo, "sess-claude");
    let out = home.hook_env("claude", &ev, &[("PROMETHEUS_KIT_NO_METRICS", "1")]);
    assert_eq!(out.status.code(), Some(0));
    // An empty value still counts as present and disables writes.
    let out_empty = home.hook_env("claude", &ev, &[("PROMETHEUS_KIT_NO_METRICS", "")]);
    assert_eq!(out_empty.status.code(), Some(0));
    let reply: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        reply["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap()
            .contains("compact --mode test"),
        "opt-out must not change the rewrite reply"
    );
    assert!(
        out.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !home.metrics_file().exists(),
        "opt-out must not create savings.jsonl"
    );

    let totals = home.metrics();
    assert_eq!(totals.status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&totals.stdout).unwrap();
    assert_eq!(parsed["by_host"], serde_json::json!({}));
    assert_eq!(parsed["by_rule"], serde_json::json!({}));
}

#[test]
fn metrics_path_obstruction_keeps_hook_stdout_identical() {
    let good = MetricsHome::new("obstruct_ok");
    let bad = MetricsHome::new("obstruct_bad");
    // `.agents` as a regular file blocks the fd walk before any write.
    fs::write(bad.home.join(".agents"), b"not a directory").unwrap();

    let ev = rewrite_event("Bash", &good.repo, "sess-claude");
    let out_good = good.hook("claude", &ev);
    let out_bad = bad.hook("claude", &ev);
    assert_eq!(out_good.status.code(), Some(0));
    assert_eq!(out_bad.status.code(), Some(0));
    assert_eq!(
        out_good.stdout, out_bad.stdout,
        "metrics obstruction must not change the hook reply"
    );
    assert!(good.metrics_file().exists());
    assert!(!bad.metrics_file().exists());
}

#[test]
#[cfg(unix)]
fn metrics_refuses_insecure_dirs_symlinks_and_loose_files() {
    use std::os::unix::fs::PermissionsExt;

    // A metrics dir with group/other bits is refused, not repaired.
    let home = MetricsHome::new("insecure_metrics");
    let metrics_dir = home.home.join(".agents/prometheus/metrics");
    fs::create_dir_all(&metrics_dir).unwrap();
    fs::set_permissions(&metrics_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let ev = rewrite_event("Bash", &home.repo, "sess-claude");
    let out = home.hook("claude", &ev);
    assert_eq!(out.status.code(), Some(0));
    assert!(!metrics_dir.join("savings.jsonl").exists());

    // A symlinked path component is refused outright.
    let linked = MetricsHome::new("symlink_metrics");
    let real = linked._root.0.join("real_agents");
    let real_metrics = real.join("prometheus/metrics");
    fs::create_dir_all(&real_metrics).unwrap();
    fs::set_permissions(&real_metrics, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&real, linked.home.join(".agents")).unwrap();
    let out = linked.hook("claude", &ev);
    assert_eq!(out.status.code(), Some(0));
    assert!(!real_metrics.join("savings.jsonl").exists());

    // A group/other-readable savings.jsonl is refused for writes.
    let loose = MetricsHome::new("loose_metrics");
    let loose_file = loose.metrics_file();
    fs::create_dir_all(loose_file.parent().unwrap()).unwrap();
    fs::set_permissions(
        loose_file.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::write(&loose_file, "{}\n").unwrap();
    fs::set_permissions(&loose_file, fs::Permissions::from_mode(0o644)).unwrap();
    let out = loose.hook("claude", &ev);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(fs::read_to_string(&loose_file).unwrap(), "{}\n");
}

#[test]
fn metrics_file_stops_accepting_rows_at_cap() {
    let home = MetricsHome::new("cap_metrics");
    let ev = rewrite_event("Bash", &home.repo, "sess-claude");
    let out = home.hook("claude", &ev);
    assert_eq!(out.status.code(), Some(0));
    assert!(home.metrics_file().exists());

    // Fill the fixture to exactly the cap with valid rows plus a truncated tail.
    let row = br#"{"timestamp":1,"host":"claude","rule_id":"shell-rewrite","raw_bytes":1,"emitted_bytes":2}"#;
    let mut data = Vec::with_capacity(METRICS_MAX_BYTES + row.len());
    while data.len() < METRICS_MAX_BYTES {
        data.extend_from_slice(row);
        data.push(b'\n');
    }
    data.truncate(METRICS_MAX_BYTES);
    assert_eq!(data.len(), METRICS_MAX_BYTES);
    fs::write(home.metrics_file(), &data).unwrap();

    let out = home.hook("claude", &ev);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        fs::metadata(home.metrics_file()).unwrap().len(),
        METRICS_MAX_BYTES as u64,
        "append must stop at the byte cap"
    );
}

fn kit_stdin(home: &MetricsHome, args: &[&str], bytes: &[u8]) -> Output {
    kit_stdin_env(home, args, bytes, &[])
}

fn kit_stdin_env(home: &MetricsHome, args: &[&str], bytes: &[u8], envs: &[(&str, &str)]) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut cmd = home.command(args);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn prometheus-kit");
    child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn metrics_records_each_clipped_output_command() {
    let home = MetricsHome::new("verbs_metrics");
    let work = home.repo.join("work");
    fs::create_dir_all(work.join("srch")).unwrap();

    // compact via stdin: raw_bytes is the exact pre-decode byte count,
    // including bytes that are not valid UTF-8.
    let mut stdin_bytes = b"line one\n".to_vec();
    stdin_bytes.extend_from_slice(&[0xff, 0xfe, b'\n']);
    stdin_bytes.extend_from_slice(b"line two\nline two\n");
    let compact_stdin = kit_stdin(
        &home,
        &["compact", "--no-spillover", "--tail", "5"],
        &stdin_bytes,
    );
    assert_eq!(compact_stdin.status.code(), Some(0));
    let compact_stdin_stdout = compact_stdin.stdout.len();

    // compact -- <cmd>: raw_bytes is child stdout + stderr byte totals before
    // lossy conversion. Unix uses sh printf emitting one non-UTF8 byte each
    // way (raw = 4); Windows cmd echo whitespace is platform-dependent, so
    // the expected total is measured by running the same argv once.
    #[cfg(unix)]
    let cmd_argv: &[&str] = &["sh", "-c", "printf 'O\\377'; printf 'E\\376' >&2"];
    #[cfg(windows)]
    let cmd_argv: &[&str] = &["cmd", "/D", "/C", "echo O&1>&2 echo E"];
    #[cfg(unix)]
    let expected_cmd_raw = 4u64;
    #[cfg(windows)]
    let expected_cmd_raw = {
        let probe = Command::new(cmd_argv[0])
            .args(&cmd_argv[1..])
            .output()
            .unwrap();
        assert!(probe.status.success());
        assert!(!probe.stdout.is_empty() && !probe.stderr.is_empty());
        (probe.stdout.len() + probe.stderr.len()) as u64
    };
    let mut argv: Vec<&str> = vec!["compact", "--no-spillover", "--"];
    argv.extend_from_slice(cmd_argv);
    let compact_cmd = home.command(&argv).output().unwrap();
    assert_eq!(compact_cmd.status.code(), Some(0));
    let compact_cmd_stdout = compact_cmd.stdout.len();

    // outline: raw is the whole source file; tight budget forces a clip.
    let mut big_rs = String::new();
    for i in 0..60 {
        big_rs.push_str(&format!("pub fn func_{i}(x: usize) -> usize {{ x + {i} }}\n"));
    }
    let rs_path = work.join("big.rs");
    fs::write(&rs_path, &big_rs).unwrap();
    let outline = home
        .command(&[
            "outline",
            "--max-tokens",
            "60",
            rs_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(outline.status.code(), Some(0));
    let outline_stdout = outline.stdout.len();

    // slice: raw is only the merged selected span, not the whole file.
    let mut rows = String::new();
    for i in 1..=120 {
        rows.push_str(&format!("row {i:03} filler text goes here\n"));
    }
    let txt_path = work.join("rows.txt");
    fs::write(&txt_path, &rows).unwrap();
    let expected_slice_raw: usize = rows
        .lines()
        .skip(49)
        .take(6)
        .map(|l| l.len() + 1)
        .sum();
    assert!(expected_slice_raw < rows.len());
    let slice = home
        .command(&[
            "slice",
            "--max-tokens",
            "30",
            &format!("{}:50-55", txt_path.display()),
        ])
        .output()
        .unwrap();
    assert_eq!(slice.status.code(), Some(0));
    let slice_stdout = slice.stdout.len();

    // search: raw is the matching raw line only; the large nonmatching
    // regions around it must not be charged.
    let match_line = format!("{}NEEDLE{}", "a".repeat(200), "b".repeat(200));
    let expected_search_raw = match_line.len() + 1;
    let mut hay = String::new();
    for _ in 0..300 {
        hay.push_str("nothing to see here\n");
    }
    hay.push_str(&match_line);
    hay.push('\n');
    for _ in 0..300 {
        hay.push_str("still nothing\n");
    }
    let srch_dir = work.join("srch");
    fs::write(srch_dir.join("haystack.txt"), &hay).unwrap();
    let search = home
        .command(&[
            "search",
            "--max-line-chars",
            "60",
            "NEEDLE",
            srch_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(search.status.code(), Some(0));
    let search_stdout = search.stdout.len();

    // map: tight budget clips the unbudgeted render.
    for i in 0..10 {
        fs::write(work.join(format!("f{i}.txt")), format!("content {i}\n")).unwrap();
    }
    let map = home
        .command(&["map", "--max-tokens", "40", work.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(map.status.code(), Some(0));
    let map_stdout = map.stdout.len();

    // diff: a real git repo; Cargo.lock is excluded noise so the run is a
    // recorded reduction even though the diff itself is small.
    let git = |args: &[&str]| {
        let st = Command::new("git")
            .arg("-C")
            .arg(&home.repo)
            .args(args)
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?} failed");
    };
    git(&["init"]);
    git(&["config", "user.email", "t@example.com"]);
    git(&["config", "user.name", "Test"]);
    fs::write(home.repo.join("src.rs"), "pub fn a() {}\n").unwrap();
    fs::write(home.repo.join("Cargo.lock"), "# v1\n").unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-m", "init"]);
    fs::write(home.repo.join("src.rs"), "pub fn a() {}\npub fn b() {}\n").unwrap();
    fs::write(home.repo.join("Cargo.lock"), "# v2\n").unwrap();
    let diff = home
        .command(&["diff", "--root", home.repo.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(diff.status.code(), Some(0));
    let diff_stdout = diff.stdout.len();

    let rows = home.rows();
    assert_eq!(rows.len(), 7, "rows: {rows:?}");
    for row in &rows {
        assert_metric_row_keys(row);
        assert_eq!(row["host"].as_str(), Some("standalone"), "row: {row}");
    }

    let compacts: Vec<&Value> = rows
        .iter()
        .filter(|r| r["rule_id"].as_str() == Some("compact"))
        .collect();
    assert_eq!(compacts.len(), 2, "rows: {rows:?}");
    let stdin_row = compacts
        .iter()
        .find(|r| r["raw_bytes"].as_u64() == Some(stdin_bytes.len() as u64))
        .expect("compact stdin row with exact raw byte count");
    assert_eq!(
        stdin_row["emitted_bytes"].as_u64().unwrap() as usize,
        compact_stdin_stdout
    );
    let cmd_row = compacts
        .iter()
        .find(|r| r["raw_bytes"].as_u64() == Some(expected_cmd_raw))
        .expect("compact command row with stdout+stderr byte total");
    assert_eq!(
        cmd_row["emitted_bytes"].as_u64().unwrap() as usize,
        compact_cmd_stdout
    );

    let checks: [(&str, usize, u64); 5] = [
        ("outline", outline_stdout, big_rs.len() as u64),
        ("slice", slice_stdout, expected_slice_raw as u64),
        ("search", search_stdout, expected_search_raw as u64),
        ("map", map_stdout, 0),
        ("diff", diff_stdout, 0),
    ];
    for (rule, stdout_len, expected_raw) in checks {
        let row = rows
            .iter()
            .find(|r| r["rule_id"].as_str() == Some(rule))
            .unwrap_or_else(|| panic!("missing metrics row for {rule}"));
        assert_eq!(
            row["emitted_bytes"].as_u64().unwrap() as usize,
            stdout_len,
            "rule={rule}"
        );
        if expected_raw != 0 {
            assert_eq!(row["raw_bytes"].as_u64().unwrap(), expected_raw, "rule={rule}");
        } else {
            assert!(row["raw_bytes"].as_u64().unwrap() > 0, "rule={rule}");
        }
    }

    let totals = home.metrics();
    assert_eq!(totals.status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&totals.stdout).unwrap();
    assert_eq!(parsed["by_rule"]["compact"]["count"], 2);
    for rule in ["outline", "slice", "search", "diff", "map"] {
        assert_eq!(parsed["by_rule"][rule]["count"], 1, "rule={rule}");
    }
    assert_eq!(parsed["by_host"]["standalone"]["count"], 7);
}

#[test]
fn metrics_search_files_only_charges_capped_files() {
    let home = MetricsHome::new("files_only_cap");
    let dir = home.repo.join("cap");
    fs::create_dir_all(&dir).unwrap();
    for i in 0..5 {
        fs::write(dir.join(format!("f{i}.txt")), "xxNEEDLEyy\n").unwrap();
    }
    let root = dir.to_str().unwrap();

    // Uncapped: all five paths shown, emitted exceeds raw -> nothing reduced,
    // so no row is recorded at all.
    let full = home
        .command(&["search", "--files-only", "--max-files", "0", "NEEDLE", root])
        .output()
        .unwrap();
    assert_eq!(full.status.code(), Some(0));
    assert!(
        !home.metrics_file().exists(),
        "unclipped files-only listing must not record"
    );

    // Capped: only one path is shown, but raw_bytes must still charge the
    // display path of every matching file, including the four omitted ones.
    let capped = home
        .command(&["search", "--files-only", "--max-files", "1", "NEEDLE", root])
        .output()
        .unwrap();
    assert_eq!(capped.status.code(), Some(0));
    assert!(capped.stdout.len() < full.stdout.len());

    // Expected raw: sum of (display path length + 1) over all five matches.
    let expected_raw: usize = (0..5)
        .map(|i| dir.join(format!("f{i}.txt")).to_string_lossy().len() + 1)
        .sum();

    let rows = home.rows();
    assert_eq!(rows.len(), 1, "rows: {rows:?}");
    let row = &rows[0];
    assert_eq!(row["rule_id"].as_str(), Some("search"), "row: {row}");
    assert_metric_row_keys(row);
    assert_eq!(
        row["raw_bytes"].as_u64().unwrap() as usize, expected_raw,
        "files beyond --max-files must still charge raw path bytes; row: {row}"
    );
    assert_eq!(
        row["emitted_bytes"].as_u64().unwrap() as usize,
        capped.stdout.len()
    );
}

#[test]
fn metrics_diff_stat_on_clean_tree_records_nothing() {
    let home = MetricsHome::new("diff_stat_clean");
    let git = |args: &[&str]| {
        let st = Command::new("git")
            .arg("-C")
            .arg(&home.repo)
            .args(args)
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?} failed");
    };
    git(&["init"]);
    git(&["config", "user.email", "t@example.com"]);
    git(&["config", "user.name", "Test"]);
    fs::write(home.repo.join("src.rs"), "pub fn a() {}\n").unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-m", "init"]);

    // --stat on an empty diff filters nothing: no reduction, no row.
    let out = home
        .command(&["diff", "--stat", "--root", home.repo.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        !home.metrics_file().exists(),
        "unclipped empty diff must not create the metrics store"
    );
}

#[test]
fn metrics_slice_signatures_only_charges_full_span() {
    let home = MetricsHome::new("slice_sig_span");
    let mut src = String::from("fn big() {\n");
    for i in 0..40 {
        src.push_str(&format!("    let v{i} = {i};\n"));
    }
    src.push_str("}\n");
    let path = home.repo.join("big.rs");
    fs::write(&path, &src).unwrap();

    let out = home
        .command(&[
            "slice",
            "--signatures-only",
            &format!("{}::big", path.display()),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout_len = out.stdout.len();

    let rows = home.rows();
    assert_eq!(rows.len(), 1, "rows: {rows:?}");
    let row = &rows[0];
    assert_eq!(row["rule_id"].as_str(), Some("slice"), "row: {row}");
    assert_metric_row_keys(row);
    // Raw is the whole multi-line interval, not just the emitted signature.
    assert_eq!(
        row["raw_bytes"].as_u64().unwrap(),
        src.len() as u64,
        "row: {row}"
    );
    assert_eq!(
        row["emitted_bytes"].as_u64().unwrap() as usize,
        stdout_len
    );
}

#[test]
fn metrics_totals_skips_malformed_non_utf8_row() {
    use std::io::Write;
    let home = MetricsHome::new("totals_malformed");
    // Seed a real row through the normal path so the store exists with the
    // platform-correct private permissions.
    let seed = kit_stdin(&home, &["compact", "--no-spillover"], b"seed line\n");
    assert_eq!(seed.status.code(), Some(0));

    // Append a non-UTF-8 malformed line followed by a valid handcrafted row.
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(home.metrics_file())
        .unwrap();
    f.write_all(b"\xff\xfe not json\n").unwrap();
    f.write_all(
        b"{\"timestamp\":1,\"host\":\"claude\",\"rule_id\":\"shell-rewrite\",\"raw_bytes\":10,\"emitted_bytes\":5}\n",
    )
    .unwrap();
    drop(f);

    let totals = home.metrics();
    assert_eq!(totals.status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&totals.stdout).unwrap();
    // The malformed line must be skipped, not stop the scan: both valid rows count.
    assert_eq!(parsed["by_rule"]["compact"]["count"], 1, "{parsed}");
    assert_eq!(parsed["by_rule"]["shell-rewrite"]["count"], 1, "{parsed}");
    assert_eq!(parsed["by_rule"]["shell-rewrite"]["raw_bytes"], 10, "{parsed}");
    assert_eq!(parsed["by_host"]["claude"]["count"], 1, "{parsed}");
}

#[test]
fn metrics_host_marker_single_vs_ambiguous() {
    let home = MetricsHome::new("host_markers");
    // One known marker -> that host.
    let single = kit_stdin_env(
        &home,
        &["compact", "--no-spillover"],
        b"squeeze\n",
        &[("CLAUDECODE", "1")],
    );
    assert_eq!(single.status.code(), Some(0));
    // Two distinct markers -> ambiguous -> standalone.
    let ambiguous = kit_stdin_env(
        &home,
        &["compact", "--no-spillover"],
        b"squeeze\n",
        &[("CLAUDECODE", "1"), ("CURSOR_PROJECT_DIR", "/tmp/ambiguous")],
    );
    assert_eq!(ambiguous.status.code(), Some(0));

    let rows = home.rows();
    assert_eq!(rows.len(), 2, "rows: {rows:?}");
    assert_eq!(rows[0]["host"].as_str(), Some("claude"), "row: {}", rows[0]);
    assert_eq!(
        rows[1]["host"].as_str(),
        Some("standalone"),
        "row: {}",
        rows[1]
    );
    for row in &rows {
        assert_eq!(row["rule_id"].as_str(), Some("compact"), "row: {row}");
        assert_metric_row_keys(row);
    }
}

#[cfg(windows)]
#[test]
fn metrics_windows_refuses_hardlinked_store() {
    let home = MetricsHome::new("win_hardlink");
    let seed = kit_stdin(&home, &["compact", "--no-spillover"], b"seed line\n");
    assert_eq!(seed.status.code(), Some(0));
    assert_eq!(home.rows().len(), 1);

    // A second name for savings.jsonl makes nNumberOfLinks > 1; the store
    // must be refused for both reads and writes rather than repaired.
    fs::hard_link(home.metrics_file(), home.metrics_file().with_file_name("alias.jsonl"))
        .unwrap();

    let next = kit_stdin(&home, &["compact", "--no-spillover"], b"more\n");
    assert_eq!(next.status.code(), Some(0));
    assert_eq!(
        home.rows().len(),
        1,
        "hard-linked store must refuse appends"
    );
}

#[cfg(windows)]
#[test]
fn metrics_windows_refuses_permissive_metrics_dir() {
    let home = MetricsHome::new("win_permissive_dir");
    let seed = kit_stdin(&home, &["compact", "--no-spillover"], b"seed line\n");
    assert_eq!(seed.status.code(), Some(0));
    assert_eq!(home.rows().len(), 1);

    // Grant BUILTIN\Users read on the isolated metrics dir only; the foreign
    // SID in the DACL must make open_metrics refuse the store.
    let metrics_dir = home
        .home
        .join(".agents")
        .join("prometheus")
        .join("metrics");
    let st = Command::new("icacls")
        .arg(&metrics_dir)
        .args(["/grant", "*S-1-5-32-545:(OI)(CI)R"])
        .status()
        .unwrap();
    assert!(st.success(), "icacls grant failed on test fixture");

    let next = kit_stdin(&home, &["compact", "--no-spillover"], b"more\n");
    assert_eq!(next.status.code(), Some(0));
    assert_eq!(
        home.rows().len(),
        1,
        "permissive metrics dir must refuse appends"
    );
}

// ---------------------------------------------------------------------------
// compact --keep-log: truncated-runner hook rewrites capture the runner once,
// persist the raw merged bytes in a private temp log, and fall back to
// byte-exact stdout when the private route cannot be established.
// ---------------------------------------------------------------------------

fn keep_log_event(command: &str, cwd: &Path) -> Value {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Execute",
        "tool_input": {"command": command, "summary": "s", "riskLevel": "low", "timeout": 30},
        "cwd": cwd.to_str().unwrap(),
        "session_id": "sess-keeplog",
    })
}

#[cfg(unix)]
fn fake_executable(dir: &Path, name: &str, script: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[cfg(unix)]
fn fixture_path(fakebin: &Path) -> String {
    format!("{}:{}", fakebin.display(), std::env::var("PATH").unwrap())
}

#[cfg(unix)]
#[test]
fn keep_log_rewrite_runs_runner_once_and_preserves_raw_log() {
    let home = MetricsHome::new("keeplog_exec");
    let fakebin = home.repo.join("fakebin");
    fs::create_dir_all(&fakebin).unwrap();
    let marker = home.repo.join("dotnet-ran.marker");
    // dash printf octal escapes: \377 \376 are invalid UTF-8, \033 is ESC,
    // \r is CR; the output deliberately ends without a newline.
    fake_executable(
        &fakebin,
        "dotnet",
        &format!(
            "#!/bin/sh\n\
             echo ran >> '{}'\n\
             printf 'out-1\\n'\n\
             printf 'err-1\\n' >&2\n\
             printf 'out-2\\r\\n'\n\
             printf '\\033[31mRED\\033[0m\\n'\n\
             printf '\\377\\376tail'\n\
             exit 23\n",
            marker.display()
        ),
    );
    let expected_raw: &[u8] = b"out-1\nerr-1\nout-2\r\n\x1b[31mRED\x1b[0m\n\xff\xfetail";

    // Consume the real hook reply, then execute the rewritten command.
    let ev = keep_log_event("dotnet test | tail -40", &home.repo);
    let hook_out = home.hook("droid", &ev);
    assert_eq!(hook_out.status.code(), Some(0));
    let reply: Value = serde_json::from_slice(&hook_out.stdout).unwrap();
    let rewritten = reply["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .expect("piped runner rewrites to keep-log compact");
    assert!(
        rewritten.contains("compact --mode test --keep-log -- dotnet test"),
        "rewritten={rewritten}"
    );
    // Untouched event fields survive the rewrite.
    let updated = &reply["hookSpecificOutput"]["updatedInput"];
    assert_eq!(updated["summary"], "s");
    assert_eq!(updated["riskLevel"], "low");
    assert_eq!(updated["timeout"], 30);

    let run = Command::new("sh")
        .arg("-c")
        .arg(rewritten)
        .env("HOME", &home.home)
        .env("USERPROFILE", &home.home)
        .env("XDG_RUNTIME_DIR", &home.runtime)
        .env("PATH", fixture_path(&fakebin))
        .env("PROMETHEUS_KIT_NO_METRICS", "1")
        .output()
        .expect("failed to execute rewritten command");

    // Runner status is preserved end-to-end.
    assert_eq!(
        run.status.code(),
        Some(23),
        "stderr={}",
        String::from_utf8_lossy(&run.stderr)
    );
    // The runner executed exactly once.
    assert_eq!(fs::read_to_string(&marker).unwrap(), "ran\n");
    // The summary leads with a printable log pointer.
    let stdout = String::from_utf8_lossy(&run.stdout);
    let log_path = stdout
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("log: "))
        .expect("keep-log output leads with the log pointer");
    assert!(stdout.contains("exit 23"), "stdout={stdout}");
    // The private log holds the exact merged bytes, ordering included.
    assert_eq!(fs::read(log_path).unwrap(), expected_raw);
    let kit_logs = home.runtime.join("prometheus").join("kit-logs");
    assert_eq!(fs::read_dir(&kit_logs).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn keep_log_short_success_and_plain_compact_writes_no_log() {
    let home = MetricsHome::new("keeplog_short");
    let fakebin = home.repo.join("fakebin");
    fs::create_dir_all(&fakebin).unwrap();
    fake_executable(&fakebin, "npm", "#!/bin/sh\nprintf 'all tests passed\\n'\nexit 0\n");
    let path = fixture_path(&fakebin);

    // A short successful keep-log run still keeps the raw log.
    let out = home
        .command(&["compact", "--mode", "test", "--keep-log", "--", "npm", "test"])
        .env("PATH", &path)
        .env("PROMETHEUS_KIT_NO_METRICS", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let log_path = stdout
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("log: "))
        .expect("keep-log leads with the log pointer");
    assert_eq!(fs::read(log_path).unwrap(), b"all tests passed\n");

    // An ordinary non-truncated short command spills nothing.
    let kit_logs = home.runtime.join("prometheus").join("kit-logs");
    let before = fs::read_dir(&kit_logs).map(|d| d.count()).unwrap_or(0);
    let plain = home
        .command(&["compact", "--mode", "test", "--", "npm", "test"])
        .env("PATH", &path)
        .env("PROMETHEUS_KIT_NO_METRICS", "1")
        .output()
        .unwrap();
    assert_eq!(plain.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&plain.stdout).contains("log:"));
    let after = fs::read_dir(&kit_logs).map(|d| d.count()).unwrap_or(0);
    assert_eq!(before, after, "plain compact must not create spillover logs");
}

#[cfg(unix)]
#[test]
fn keep_log_private_route_failure_falls_back_to_raw_stdout() {
    let home = MetricsHome::new("keeplog_fallback");
    let fakebin = home.repo.join("fakebin");
    fs::create_dir_all(&fakebin).unwrap();
    let marker = home.repo.join("dotnet-ran.marker");
    fake_executable(
        &fakebin,
        "dotnet",
        &format!(
            "#!/bin/sh\n\
             echo ran >> '{}'\n\
             printf 'bad-\\377\\376-output\\r\\n'\n\
             printf 'no-newline-tail'\n\
             exit 23\n",
            marker.display()
        ),
    );
    let expected_raw: &[u8] = b"bad-\xff\xfe-output\r\nno-newline-tail";

    // Obstruct the runtime slot: XDG_RUNTIME_DIR/prometheus is a plain file,
    // so no private kit-logs directory can be established. The fixture root
    // is pinned owner-only first so the ancestor walk accepts it and the
    // obstruction — not an insecure parent — is what refuses the route.
    let obstruct = TempDir::new("keeplog_obstruct");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&obstruct.0, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(obstruct.0.join("prometheus"), b"occupied").unwrap();

    let out = home
        .command(&["compact", "--mode", "test", "--keep-log", "--", "dotnet", "test"])
        .env("PATH", fixture_path(&fakebin))
        .env("XDG_RUNTIME_DIR", &obstruct.0)
        .env("PROMETHEUS_KIT_NO_METRICS", "1")
        .output()
        .unwrap();

    // Fallback emits the captured bytes unchanged — invalid UTF-8, CR, and
    // no synthetic trailing newline — with the runner's own status, once.
    assert_eq!(out.status.code(), Some(23));
    assert_eq!(out.stdout, expected_raw, "fallback must be byte-exact");
    assert!(out.stderr.is_empty(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(fs::read_to_string(&marker).unwrap(), "ran\n");
}

#[test]
fn keep_log_rejects_conflicting_options_before_execution() {
    for args in [
        &["compact", "--keep-log"][..],
        &["compact", "--keep-log", "--json", "--", "dotnet", "test"][..],
        &["compact", "--keep-log", "--no-spillover", "--", "dotnet", "test"][..],
        &[
            "compact",
            "--keep-log",
            "--save-log",
            "x.log",
            "--",
            "dotnet",
            "test",
        ][..],
        &["compact", "--keep-log", "somefile.txt"][..],
    ] {
        let out = run_kit(args, None);
        assert_eq!(out.status.code(), Some(2), "args={args:?}");
    }
}

#[test]
fn keep_log_issue_examples_trace_with_and_without_rtk() {
    let home = MetricsHome::new("keeplog_examples");
    // (command, expected rewritten tail, rtk claims it in piped form)
    let cases: &[(&str, &str, bool)] = &[
        ("dotnet test", "compact --mode test -- dotnet test", false),
        (
            "dotnet test | tail -40",
            "compact --mode test --keep-log -- dotnet test",
            false,
        ),
        (
            "pytest tests -q 2>&1 | tail -20",
            "compact --mode test --keep-log -- pytest tests -q",
            true,
        ),
        (
            "npm test 2>&1 | head -50",
            "compact --mode test --keep-log -- npm test",
            false,
        ),
    ];
    for rtk in [false, true] {
        for &(command, expected_tail, rtk_claims) in cases {
            let ev = keep_log_event(command, &home.repo);
            let extra: &[(&str, &str)] = if rtk {
                &[("PROMETHEUS_KIT_RTK_COEXIST", "1")]
            } else {
                &[]
            };
            let out = home.hook_env("droid", &ev, extra);
            assert_eq!(out.status.code(), Some(0), "rtk={rtk} cmd={command}");
            let reply: Value = serde_json::from_slice(&out.stdout).unwrap();
            let rewritten = reply
                .pointer("/hookSpecificOutput/updatedInput/command")
                .and_then(Value::as_str);
            if rtk && rtk_claims {
                assert!(
                    rewritten.is_none(),
                    "rtk={rtk} cmd={command} must defer to RTK: {reply}"
                );
                continue;
            }
            let rewritten = rewritten.unwrap_or_else(|| {
                panic!("no rewrite rtk={rtk} cmd={command} reply={reply}")
            });
            assert!(
                rewritten.contains(expected_tail),
                "rtk={rtk} cmd={command} -> {rewritten}"
            );
            assert!(rewritten.contains(bin()), "kit bin missing: {rewritten}");
            // Only the piped forms carry --keep-log.
            assert_eq!(
                command.contains('|'),
                rewritten.contains("--keep-log"),
                "rtk={rtk} cmd={command} -> {rewritten}"
            );
            // Untouched fields are preserved.
            let updated = &reply["hookSpecificOutput"]["updatedInput"];
            assert_eq!(updated["summary"], "s");
            assert_eq!(updated["riskLevel"], "low");
            assert_eq!(updated["timeout"], 30);
        }
    }
}

#[test]
fn keep_log_secret_command_passes_through_without_rewrite_or_ask() {
    let home = MetricsHome::new("keeplog_secret");
    let ev = keep_log_event("dotnet test --settings .env | tail -5", &home.repo);
    let out = home.hook("droid", &ev);
    assert_eq!(out.status.code(), Some(0));
    let reply: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        reply,
        serde_json::json!({}),
        "shell commands with secret file operands must neither ask nor rewrite to keep-log: {reply}"
    );
}

#[cfg(unix)]
fn keep_log_fake_runner(fakebin: &Path) {
    fake_executable(
        fakebin,
        "dotnet",
        "#!/bin/sh\nprintf 'raw-out\\377\\n'\nprintf 'err-line\\376\\n' >&2\nexit 7\n",
    );
}

#[cfg(unix)]
#[test]
fn keep_log_git_tree_or_cwd_runtime_falls_back_without_dirs() {
    let home = MetricsHome::new("keeplog_gittree");
    let fakebin = home.repo.join("fakebin");
    fs::create_dir_all(&fakebin).unwrap();
    keep_log_fake_runner(&fakebin);
    let args = [
        "compact", "--mode", "test", "--keep-log", "--", "dotnet", "test",
    ];
    let expected: &[u8] = b"raw-out\xff\nerr-line\xfe\n";
    let run_with = |rt: &Path, cwd: &Path| {
        home.command(&args)
            .env("PATH", fixture_path(&fakebin))
            .env("XDG_RUNTIME_DIR", rt)
            .env("PROMETHEUS_KIT_NO_METRICS", "1")
            .current_dir(cwd)
            .output()
            .unwrap()
    };

    // Runtime dir is a sibling of the nested cwd inside a synthetic git tree:
    // the canonical parent has a `.git` ancestor, so the route is refused.
    let repo = TempDir::new("keeplog_repo");
    fs::create_dir_all(repo.0.join(".git")).unwrap();
    let rt = repo.0.join("rt");
    fs::create_dir_all(&rt).unwrap();
    let nested = repo.0.join("a").join("b");
    fs::create_dir_all(&nested).unwrap();
    let out = run_with(&rt, &nested);
    assert_eq!(out.status.code(), Some(7), "stdout={:?}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(out.stdout, expected, "byte-exact raw fallback");
    assert_eq!(fs::read_dir(&rt).unwrap().count(), 0, "no dirs in repo runtime");

    // Via symlink the canonical parent resolves into the same git tree.
    let linkdir = TempDir::new("keeplog_link");
    let link = linkdir.0.join("rtlink");
    std::os::unix::fs::symlink(&rt, &link).unwrap();
    let out = run_with(&link, &nested);
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(out.stdout, expected);
    assert_eq!(fs::read_dir(&rt).unwrap().count(), 0);

    // An unrelated world-writable non-sticky runtime parent also falls back.
    let badroot = TempDir::new("keeplog_insec");
    let bad = badroot.0.join("rt");
    fs::create_dir_all(&bad).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o777)).unwrap();
    }
    let out = run_with(&bad, &nested);
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(out.stdout, expected);
    assert_eq!(fs::read_dir(&bad).unwrap().count(), 0, "no dirs in insecure parent");
}

#[cfg(unix)]
#[test]
fn keep_log_tiny_budget_keeps_pointer_only() {
    let home = MetricsHome::new("keeplog_tiny");
    let out = home
        .command(&[
            "compact",
            "--mode",
            "test",
            "--keep-log",
            "--max-tokens",
            "3",
            "--",
            "sh",
            "-c",
            "printf 'tiny-out\\n'",
        ])
        .env("PROMETHEUS_KIT_NO_METRICS", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "tiny budget must keep only the pointer: {stdout:?}");
    let log = lines[0].strip_prefix("log: ").expect("pointer line");
    assert_eq!(fs::read(log).unwrap(), b"tiny-out\n");
}

#[cfg(unix)]
#[test]
fn keep_log_spawn_failures_use_shell_status() {
    use std::os::unix::fs::PermissionsExt;
    let home = MetricsHome::new("keeplog_spawn");
    let out = home
        .command(&["compact", "--keep-log", "--", "definitely-missing-bin-9x7"])
        .env("PROMETHEUS_KIT_NO_METRICS", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(127), "missing binary -> 127");
    let fakebin = home.repo.join("fakebin");
    fs::create_dir_all(&fakebin).unwrap();
    let noexec = fakebin.join("noexec");
    fs::write(&noexec, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&noexec, fs::Permissions::from_mode(0o644)).unwrap();
    let out = home
        .command(&["compact", "--keep-log", "--", noexec.to_str().unwrap()])
        .env("PROMETHEUS_KIT_NO_METRICS", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(126), "non-executable -> 126");
}

#[cfg(windows)]
#[test]
fn keep_log_windows_private_route_writes_log() {
    let home = MetricsHome::new("keeplog_win");
    let wintemp = home.repo.join("wintemp");
    fs::create_dir_all(&wintemp).unwrap();
    let out = home
        .command(&[
            "compact",
            "--mode",
            "test",
            "--keep-log",
            "--",
            "cmd",
            "/d",
            "/c",
            "echo O&1>&2 echo E",
        ])
        .env("TEMP", &wintemp)
        .env("TMP", &wintemp)
        .env("PROMETHEUS_KIT_NO_METRICS", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    let log = lines
        .first()
        .and_then(|l| l.strip_prefix("log: "))
        .expect("log pointer");
    let bytes = fs::read(log).expect("private log readable");
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains('O') && text.contains('E'), "log={text:?}");
}

#[test]
fn slice_partial_success_emits_valid_results_diagnostics_json_and_metrics() {
    let home = MetricsHome::new("slice_partial");
    let rs = home.repo.join("Svc.cs");
    fs::write(
        &rs,
        b"namespace Demo;\npublic class Svc {\n    public void Ping() {}\n    public void Pong() {}\n}\n",
    )
    .unwrap();
    let missing = home.repo.join("nope.cs");
    let valid_ping = format!("{}::Svc.Ping", rs.display());
    let valid_pong = format!("{}::Svc.Pong", rs.display());
    let typo = format!("{}::Png", rs.display());
    let oob = format!("{}:999", rs.display());
    let miss_spec = format!("{}:1-2", missing.display());

    // Partial success (text): valid slices + per-spec error with closest: + exit 0
    let text_out = run_kit(&["slice", &valid_ping, &typo, &oob, &miss_spec, &valid_pong], None);
    assert_eq!(text_out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&text_out.stdout);
    assert!(stdout.contains("public void Ping()"), "{stdout}");
    assert!(stdout.contains("public void Pong()"), "{stdout}");
    assert!(stdout.contains("error:"), "{stdout}");
    assert!(stdout.contains("closest:"), "{stdout}");
    assert!(stdout.contains("Demo.Svc.Ping"), "{stdout}");
    assert!(stdout.contains("exceeds file length"), "{stdout}");
    assert!(stdout.contains("nope.cs"), "{stdout}");

    // Partial success (--json): valid JSON containing both slices and errors, exit 0
    let json_out = run_kit(&["slice", "--json", &valid_ping, &typo, &miss_spec], None);
    assert_eq!(json_out.status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&json_out.stdout).expect("valid json");
    assert_eq!(parsed["slices"].as_array().unwrap().len(), 1);
    let errs = parsed["errors"].as_array().unwrap();
    assert_eq!(errs.len(), 2);
    assert_eq!(errs[0]["spec"], typo);
    assert!(errs[0]["message"].as_str().unwrap().contains("closest:"));
    assert_eq!(errs[1]["spec"], miss_spec);

    // Total failure across multiple specs: exit 1, stderr diagnostics, JSON valid in --json
    let all_bad = run_kit(&["slice", &typo, &miss_spec], None);
    assert_eq!(all_bad.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&all_bad.stderr);
    assert!(stderr.contains("Demo.Svc.Ping"), "{stderr}");
    assert!(stderr.contains("nope.cs"), "{stderr}");
    assert!(all_bad.stdout.is_empty());

    let all_bad_json = run_kit(&["slice", "--json", &typo, &miss_spec], None);
    assert_eq!(all_bad_json.status.code(), Some(1));
    let bad_parsed: Value = serde_json::from_slice(&all_bad_json.stdout).expect("valid error json");
    assert!(bad_parsed["slices"].as_array().unwrap().is_empty());
    assert_eq!(bad_parsed["errors"].as_array().unwrap().len(), 2);

    // Partial success records Rule::Slice metric when valid output is reduced/clipped.
    let big = home.repo.join("big.txt");
    let big_content: String = (1..=120).map(|i| format!("row {i:03} filler text\n")).collect();
    fs::write(&big, &big_content).unwrap();
    let m_out = home
        .command(&[
            "slice",
            "--max-tokens",
            "30",
            &format!("{}:1-60", big.display()),
            &typo,
        ])
        .output()
        .unwrap();
    assert_eq!(m_out.status.code(), Some(0));
    let rows = home.rows();
    let row = find_row(&rows, "standalone", "slice");
    assert!(row["raw_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn outline_partial_success_emits_valid_docs_diagnostics_json_and_metrics() {
    let home = MetricsHome::new("outline_partial");
    let rs = home.repo.join("lib.rs");
    let mut rs_body = String::new();
    for i in 0..30 {
        rs_body.push_str(&format!(
            "pub fn func_{i}(x: usize) -> usize {{\n    let y = x + {i};\n    let z = y * 2;\n    z + 1\n}}\n"
        ));
    }
    fs::write(&rs, &rs_body).unwrap();
    let bin = home.repo.join("blob.rs");
    fs::write(&bin, b"\x00\x01\x02").unwrap();
    let missing = home.repo.join("missing.rs");

    // Partial success (text): valid outline + per-path error + exit 0
    let text_out = run_kit(
        &[
            "outline",
            rs.to_str().unwrap(),
            missing.to_str().unwrap(),
            bin.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(text_out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&text_out.stdout);
    assert!(stdout.contains("pub fn func_0"), "{stdout}");
    assert!(stdout.contains("error:"), "{stdout}");
    assert!(stdout.contains("missing.rs"), "{stdout}");
    assert!(stdout.contains("binary file skipped"), "{stdout}");

    // Partial success (--json, tight budget): valid JSON preserving errors alongside docs
    let json_out = run_kit(
        &[
            "outline",
            "--json",
            "--max-tokens",
            "200",
            rs.to_str().unwrap(),
            missing.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(json_out.status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&json_out.stdout).expect("valid outline json");
    assert_eq!(parsed["docs"].as_array().unwrap().len(), 1);
    let errs = parsed["errors"].as_array().unwrap();
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0]["path"], missing.to_string_lossy().as_ref());

    // Total failure: exit 1 and stderr diagnostics
    let all_bad = run_kit(&["outline", missing.to_str().unwrap(), bin.to_str().unwrap()], None);
    assert_eq!(all_bad.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&all_bad.stderr);
    assert!(stderr.contains("missing.rs"), "{stderr}");
    assert!(stderr.contains("binary file skipped"), "{stderr}");
    assert!(all_bad.stdout.is_empty());

    // Partial success records Rule::Outline metric for valid docs.
    let m_out = home
        .command(&["outline", rs.to_str().unwrap(), missing.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(m_out.status.code(), Some(0));
    let rows = home.rows();
    let row = find_row(&rows, "standalone", "outline");
    assert_eq!(row["raw_bytes"].as_u64().unwrap(), rs_body.len() as u64);

    // Total failure with --json exits 1 and emits valid JSON with errors + stderr.
    let all_bad_json = run_kit(
        &["outline", "--json", missing.to_str().unwrap(), bin.to_str().unwrap()],
        None,
    );
    assert_eq!(all_bad_json.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&all_bad_json.stderr).contains("missing.rs"));
    let bad_parsed: Value = serde_json::from_slice(&all_bad_json.stdout).expect("valid error json");
    assert!(bad_parsed["docs"].as_array().unwrap().is_empty());
    assert_eq!(bad_parsed["errors"].as_array().unwrap().len(), 2);
}

#[test]
fn partial_success_batch_edge_cases_and_budgets() {
    let tmp = TempDir::new("partial_edges");
    let cs = tmp.write(
        "Svc.cs",
        b"namespace Demo;\npublic class Svc {\n    public void Ping() {}\n    public void Pong() {}\n}\n",
    );
    let empty = tmp.write("empty.txt", b"");
    let rs = tmp.write(
        "many.rs",
        (0..40)
            .map(|i| format!("pub fn func_{i}(x: usize) -> usize {{\n    x + {i}\n}}\n"))
            .collect::<String>()
            .as_bytes(),
    );

    let valid_ping = format!("{}::Svc.Ping", cs.display());
    let typo = format!("{}::Png", cs.display());
    let empty_spec = format!("{}:1", empty.display());

    // (a) Mixed parse + runtime + valid specs preserve exact CLI error order and normalize spec.
    let padded_bad = format!("  {}  ", cs.display());
    let mixed_ok = run_kit(&["slice", "--json", &typo, &padded_bad, &empty_spec, &valid_ping], None);
    assert_eq!(mixed_ok.status.code(), Some(0));
    let mv: Value = serde_json::from_slice(&mixed_ok.stdout).unwrap();
    assert_eq!(mv["slices"].as_array().unwrap().len(), 1);
    let merrs = mv["errors"].as_array().unwrap();
    assert_eq!(merrs.len(), 3);
    assert_eq!(merrs[0]["spec"], typo);
    assert_eq!(merrs[1]["spec"], cs.to_string_lossy().as_ref());
    assert_eq!(merrs[2]["spec"], empty_spec);
    assert!(merrs[2]["message"].as_str().unwrap().contains("empty"));

    // Mixed parse + runtime errors with zero valid specs exit 1 in CLI order.
    let mixed_fail = run_kit(&["slice", &typo, &padded_bad], None);
    assert_eq!(mixed_fail.status.code(), Some(1));
    let mstderr = String::from_utf8_lossy(&mixed_fail.stderr);
    let pos_typo = mstderr.find("Demo.Svc.Ping").expect("typo error");
    let pos_parse = mstderr.find("missing range or selector").expect("parse error");
    assert!(pos_typo < pos_parse, "expected CLI order in stderr: {mstderr}");

    // Multiple all-syntax errors exit 2.
    let all_syntax = run_kit(&["slice", cs.to_str().unwrap(), &format!("{}:9-2", cs.display())], None);
    assert_eq!(all_syntax.status.code(), Some(2));

    // (b) Tight --max-tokens with many errors keeps valid results AND stays bounded (text & JSON).
    let mut missing_specs: Vec<String> = (0..12)
        .map(|i| format!("{}:1-2", tmp.0.join(format!("very_long_missing_file_name_{i:02}.rs")).display()))
        .collect();
    let mut slice_args_txt: Vec<&str> = vec!["slice", "--max-tokens", "120", &valid_ping];
    for s in &missing_specs {
        slice_args_txt.push(s);
    }
    let stxt = run_kit(&slice_args_txt, None);
    assert_eq!(stxt.status.code(), Some(0));
    let stxt_s = String::from_utf8_lossy(&stxt.stdout);
    assert!(stxt_s.contains("public void Ping()"), "{stxt_s}");
    assert!(stxt_s.contains("omitted errors"), "{stxt_s}");
    assert!(stxt.stdout.len() <= 120 * 4 + 80, "slice text exceeded budget: {}", stxt.stdout.len());

    let mut slice_args_json: Vec<&str> = vec!["slice", "--json", "--max-tokens", "160", &valid_ping];
    for s in &missing_specs {
        slice_args_json.push(s);
    }
    let sjson = run_kit(&slice_args_json, None);
    assert_eq!(sjson.status.code(), Some(0));
    assert!(sjson.stdout.len() <= 160 * 4 + 2, "slice json exceeded budget: {} bytes", sjson.stdout.len());
    let sjv: Value = serde_json::from_slice(&sjson.stdout).unwrap();
    assert!(!sjv["slices"].as_array().unwrap().is_empty(), "valid slice starved: {sjv}");
    assert_eq!(sjv["truncated"], Value::Bool(true));

    missing_specs.clear();
    let missing_paths: Vec<String> = (0..12)
        .map(|i| tmp.0.join(format!("very_long_missing_outline_path_{i:02}.rs")).to_string_lossy().into_owned())
        .collect();
    let mut out_args_txt: Vec<&str> = vec!["outline", "--max-tokens", "150", rs.to_str().unwrap()];
    for p in &missing_paths {
        out_args_txt.push(p);
    }
    let otxt = run_kit(&out_args_txt, None);
    assert_eq!(otxt.status.code(), Some(0));
    let otxt_s = String::from_utf8_lossy(&otxt.stdout);
    assert!(otxt_s.contains("pub fn func_0"), "{otxt_s}");
    assert!(otxt_s.contains("omitted errors"), "{otxt_s}");
    assert!(otxt.stdout.len() <= 150 * 4 + 80, "outline text exceeded budget: {}", otxt.stdout.len());

    let mut out_args_json: Vec<&str> = vec!["outline", "--json", "--max-tokens", "220", rs.to_str().unwrap()];
    for p in &missing_paths {
        out_args_json.push(p);
    }
    let ojson = run_kit(&out_args_json, None);
    assert_eq!(ojson.status.code(), Some(0));
    assert!(ojson.stdout.len() <= 220 * 4 + 2, "outline json exceeded budget: {} bytes", ojson.stdout.len());
    let ojv: Value = serde_json::from_slice(&ojson.stdout).unwrap();
    assert!(!ojv["docs"][0]["items"].as_array().unwrap().is_empty(), "valid outline starved: {ojv}");
    assert_eq!(ojv["truncated"], Value::Bool(true));
}

#[test]
fn metrics_records_inline_dump_denial_and_aggregates_new_hosts_and_rules() {
    let home = MetricsHome::new("adr0014_metrics");
    let big_json: String = format!(
        "{{\n{}\n}}\n",
        (0..220)
            .map(|i| format!("  \"k{i}\": {i}"))
            .collect::<Vec<_>>()
            .join(",\n")
    );
    fs::write(home.repo.join("big.json"), &big_json).unwrap();
    fs::write(home.repo.join("small.json"), "{\"a\":1}\n").unwrap();

    // Small structured file on droid stays silent and writes zero metrics.
    let small_ev = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Execute",
        "tool_input": {"command": "jq '.a' small.json"},
        "cwd": home.repo.to_str().unwrap(),
        "session_id": "sess-dump",
    });
    let s_out = home.hook("droid", &small_ev);
    assert_eq!(s_out.status.code(), Some(0));
    assert_eq!(serde_json::from_slice::<Value>(&s_out.stdout).unwrap(), serde_json::json!({}));
    assert!(!home.metrics_file().exists(), "small dump must record no phantom row");

    // Large structured file on droid denies once (inline-dump-denial), then retry allows (allowed-retry).
    let big_ev = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Execute",
        "tool_input": {"command": "jq '.k0' big.json"},
        "cwd": home.repo.to_str().unwrap(),
        "session_id": "sess-dump",
    });
    let d1 = home.hook("droid", &big_ev);
    let d1v: Value = serde_json::from_slice(&d1.stdout).unwrap();
    assert_eq!(d1v["hookSpecificOutput"]["permissionDecision"], "deny");
    let d2 = home.hook("droid", &big_ev);
    assert_eq!(serde_json::from_slice::<Value>(&d2.stdout).unwrap(), serde_json::json!({}));

    // Verify new CLI host markers (antigravity, grok) and metrics aggregation of new host/rule enums.
    let agy_cmd = kit_stdin_env(
        &home,
        &["compact", "--no-spillover"],
        b"squeeze\n",
        &[("ANTIGRAVITY_CONVERSATION_ID", "conv-1")],
    );
    assert_eq!(agy_cmd.status.code(), Some(0));
    let grok_cmd = kit_stdin_env(
        &home,
        &["compact", "--no-spillover"],
        b"squeeze\n",
        &[("GROK_SESSION_ID", "grok-1")],
    );
    assert_eq!(grok_cmd.status.code(), Some(0));

    // Append synthetic omp + shell-denial row and confirm `prometheus-kit metrics` aggregates cleanly.
    use std::io::Write;
    let mut f = fs::OpenOptions::new().append(true).open(home.metrics_file()).unwrap();
    writeln!(
        f,
        "{{\"timestamp\":1,\"host\":\"omp\",\"rule_id\":\"shell-denial\",\"raw_bytes\":12,\"emitted_bytes\":40}}"
    )
    .unwrap();
    drop(f);

    let totals = home.metrics();
    assert_eq!(totals.status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&totals.stdout).unwrap();
    assert_eq!(parsed["by_rule"]["inline-dump-denial"]["count"], 1);
    assert_eq!(parsed["by_rule"]["allowed-retry"]["count"], 1);
    assert_eq!(parsed["by_rule"]["shell-denial"]["count"], 1);
    assert_eq!(parsed["by_host"]["antigravity"]["count"], 1);
    assert_eq!(parsed["by_host"]["grok"]["count"], 1);
    assert_eq!(parsed["by_host"]["omp"]["count"], 1);
}

#[test]
fn hook_omp_rewrites_guards_unlocks_and_records_metrics() {
    let home = MetricsHome::new("hook_omp");
    let big_rs = home.repo.join("big.rs");
    fs::write(
        &big_rs,
        (0..220)
            .map(|i| format!("pub fn fn_{i}() {{}}\n"))
            .collect::<String>(),
    )
    .unwrap();
    let big_json = home.repo.join("big.json");
    fs::write(
        &big_json,
        format!(
            "{{\n{}\n}}\n",
            (0..220)
                .map(|i| format!("  \"k{i}\": {i}"))
                .collect::<Vec<_>>()
                .join(",\n")
        ),
    )
    .unwrap();

    // 1. Bash shell rewrite emits `{ input }` with untouched fields preserved.
    let rw_ev = serde_json::json!({
        "toolName": "bash",
        "input": {"command": "git status", "timeout": 45},
        "cwd": home.repo.to_str().unwrap(),
        "sessionId": "omp-int-1",
        "lastPrompt": "",
    });
    let rw_out = home.hook("omp", &rw_ev);
    assert_eq!(rw_out.status.code(), Some(0));
    let rw_val: Value = serde_json::from_slice(&rw_out.stdout).unwrap();
    assert!(rw_val["input"]["command"]
        .as_str()
        .unwrap()
        .contains("diff --status"));
    assert_eq!(rw_val["input"]["timeout"], 45);

    // 2. Four-state Guided deny-once on 220-line whole-file read.
    let read_ev = serde_json::json!({
        "toolName": "read",
        "input": {"path": big_rs.to_str().unwrap()},
        "cwd": home.repo.to_str().unwrap(),
        "sessionId": "omp-int-1",
        "lastPrompt": "",
    });
    let r1: Value = serde_json::from_slice(&home.hook("omp", &read_ev).stdout).unwrap();
    assert_eq!(r1["block"], Value::Bool(true));
    let r2: Value = serde_json::from_slice(&home.hook("omp", &read_ev).stdout).unwrap();
    assert_eq!(r2, serde_json::json!({}));
    let r3: Value = serde_json::from_slice(&home.hook("omp", &read_ev).stdout).unwrap();
    assert_eq!(r3["block"], Value::Bool(true));
    let r4: Value = serde_json::from_slice(&home.hook("omp", &read_ev).stdout).unwrap();
    assert_eq!(r4, serde_json::json!({}));

    // 3. Large inline JSON dump denies once then allows retry.
    let dump_ev = serde_json::json!({
        "toolName": "bash",
        "input": {"command": "jq '.k0' big.json"},
        "cwd": home.repo.to_str().unwrap(),
        "sessionId": "omp-int-1",
        "lastPrompt": "",
    });
    let d1: Value = serde_json::from_slice(&home.hook("omp", &dump_ev).stdout).unwrap();
    assert_eq!(d1["block"], Value::Bool(true));
    let d2: Value = serde_json::from_slice(&home.hook("omp", &dump_ev).stdout).unwrap();
    assert_eq!(d2, serde_json::json!({}));

    // 4. Secret guard blocks by default, rejects slash-adjacent generic tokens, and unlocks when named.
    let sec_blocked: Value = serde_json::from_slice(
        &home
            .hook(
                "omp",
                &serde_json::json!({
                    "toolName": "read",
                    "input": {"path": ".env"},
                    "cwd": home.repo.to_str().unwrap(),
                    "sessionId": "omp-int-1",
                    "lastPrompt": "",
                }),
            )
            .stdout,
    )
    .unwrap();
    assert_eq!(sec_blocked["block"], Value::Bool(true));
    let sec_unlocked: Value = serde_json::from_slice(
        &home
            .hook(
                "omp",
                &serde_json::json!({
                    "toolName": "read",
                    "input": {"path": ".env"},
                    "cwd": home.repo.to_str().unwrap(),
                    "sessionId": "omp-int-1",
                    "lastPrompt": "inspect .env please",
                }),
            )
            .stdout,
    )
    .unwrap();
    assert_eq!(sec_unlocked, serde_json::json!({}));
    let strict_blocked: Value = serde_json::from_slice(
        &home
            .hook(
                "omp",
                &serde_json::json!({
                    "toolName": "read",
                    "input": {"path": ".ssh/config"},
                    "cwd": home.repo.to_str().unwrap(),
                    "sessionId": "omp-int-1",
                    "lastPrompt": "debug the /config endpoint",
                }),
            )
            .stdout,
    )
    .unwrap();
    assert_eq!(strict_blocked["block"], Value::Bool(true));

    // 5. Unified metrics record all omp activity cleanly.
    let totals = home.metrics();
    assert_eq!(totals.status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&totals.stdout).unwrap();
    assert_eq!(parsed["by_host"]["omp"]["count"], 7, "{parsed}");
    assert_eq!(parsed["by_rule"]["shell-rewrite"]["count"], 1, "{parsed}");
    assert_eq!(parsed["by_rule"]["first-read-denial"]["count"], 1, "{parsed}");
    assert_eq!(parsed["by_rule"]["reread-denial"]["count"], 1, "{parsed}");
    assert_eq!(parsed["by_rule"]["inline-dump-denial"]["count"], 1, "{parsed}");
    assert_eq!(parsed["by_rule"]["allowed-retry"]["count"], 3, "{parsed}");
}
