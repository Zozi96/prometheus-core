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
    cmd.args(args);
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
