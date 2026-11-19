//! Reproducible latency and token-savings benchmark for `prometheus-kit` (`outline` + `slice`).
//!
//! Run in release mode from repo root:
//!   cargo run --release --no-default-features --locked --manifest-path core/Cargo.toml --example bench_kit

use prometheus_core::compact::{compact_text, render_compact_text, CompactMode, CompactOptions};
use prometheus_core::diff::{execute_diff, render_diff_text, DiffMode, DiffOptions};
use prometheus_core::map::{execute_map, render_map_text, MapOptions};
use prometheus_core::outline::{
    outline_source, render_outline_text, Lang, OutlineOptions,
};
use prometheus_core::search::{execute_search, render_search_text, SearchOptions};
use prometheus_core::slice::{execute_slices, parse_spec, render_slice_text, SliceOptions};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

struct BenchCase {
    name: String,
    lang: Lang,
    src: String,
    selector: String,
    ext: &'static str,
}

fn approx_tokens(s: &str) -> usize {
    s.len() / 4
}

fn median_us(mut samples_us: Vec<u128>) -> f64 {
    samples_us.sort_unstable();
    let mid = samples_us.len() / 2;
    if samples_us.len().is_multiple_of(2) {
        (samples_us[mid - 1] + samples_us[mid]) as f64 / 2.0
    } else {
        samples_us[mid] as f64
    }
}

fn synth_csharp_service(methods: usize) -> String {
    let mut s = String::from(
        "using System;\nusing System.Threading;\nusing System.Threading.Tasks;\n\nnamespace AdvDevPortal.Core.Features.TenantProvisioning;\n\npublic sealed class TenantMigrationService\n{\n",
    );
    for i in 0..methods {
        s.push_str(&format!(
            "    [Fact]\n    public async Task<bool> RunStep{i}Async(Guid tenantId, CancellationToken ct)\n    {{\n        var key = $\"tenant-{{tenantId}}-step-{i}\";\n        await Task.Delay({i}, ct);\n        return !string.IsNullOrEmpty(key);\n    }}\n\n"
        ));
    }
    s.push_str("}\n");
    s
}

fn synth_targets_json(entries: usize) -> String {
    let mut s = String::from("{\n  \"environments\": [\n");
    for i in 0..entries {
        let comma = if i + 1 < entries { "," } else { "" };
        s.push_str(&format!(
            "    {{\n      \"id\": \"env-{i}\",\n      \"host\": \"https://app-{i}.internal\",\n      \"replicas\": 3,\n      \"region\": \"us-east-1\",\n      \"features\": {{\"canary\": true, \"metrics\": true}}\n    }}{comma}\n"
        ));
    }
    s.push_str("  ],\n  \"defaults\": {\"timeoutMs\": 30000, \"retries\": 3}\n}\n");
    s
}

fn synth_jsonl(lines: usize) -> String {
    let mut s = String::new();
    for i in 0..lines {
        if i % 20 == 0 {
            s.push_str(&format!(
                "{{\"type\":\"error\",\"step\":{i},\"code\":\"E_TIMEOUT\",\"msg\":\"timeout\"}}\n"
            ));
        } else {
            s.push_str(&format!(
                "{{\"type\":\"tool_use\",\"step\":{i},\"tool\":\"Read\",\"tokens\":412}}\n"
            ));
        }
    }
    s
}

fn synth_razor(methods: usize) -> String {
    let mut s = String::from("@page \"/tenants\"\n@inject ITenantService Tenants\n\n<div class=\"panel\">\n  @for (var r = 0; r < 40; r++) { <span>@r</span> }\n</div>\n\n@code {\n    private bool _busy;\n\n");
    for i in 0..methods {
        s.push_str(&format!(
            "    public async Task Refresh{i}Async()\n    {{\n        _busy = true;\n        await Tenants.SyncAsync({i});\n        _busy = false;\n    }}\n\n"
        ));
    }
    s.push_str("}\n");
    s
}

fn synth_powershell(funcs: usize) -> String {
    let mut s = String::from("param(\n    [string]$Environment = 'staging'\n)\n\n");
    for i in 0..funcs {
        s.push_str(&format!(
            "function Invoke-Step{i} {{\n    param([string]$Target)\n    $msg = @\"\nStep {i} running on $Target\n\"@\n    Write-Output $msg\n}}\n\n"
        ));
    }
    s
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn main() {
    let root = repo_root();
    let mut cases: Vec<BenchCase> = Vec::new();

    let real_files = [
        ("core/src/check.rs", Lang::Rust, "compute_deltas", "rs"),
        ("scripts/token_report.py", Lang::Python, "main", "py"),
        ("scripts/check_package.py", Lang::Python, "main", "py"),
        ("README.md", Lang::Markdown, "Token report", "md"),
        ("runtime/prometheus_core.lock", Lang::Json, "/check_assets/macos-arm64", "json"),
    ];
    for (rel, lang, selector, ext) in real_files {
        let full = root.join(rel);
        if let Ok(src) = fs::read_to_string(&full) {
            cases.push(BenchCase {
                name: rel.to_owned(),
                lang,
                src,
                selector: selector.to_owned(),
                ext,
            });
        }
    }

    cases.push(BenchCase {
        name: "synth/TenantMigrationService.cs (180 methods)".to_owned(),
        lang: Lang::CSharp,
        src: synth_csharp_service(180),
        selector: "TenantMigrationService.RunStep120Async".to_owned(),
        ext: "cs",
    });
    cases.push(BenchCase {
        name: "synth/targets.json (420 envs)".to_owned(),
        lang: Lang::Json,
        src: synth_targets_json(420),
        selector: "/environments/250".to_owned(),
        ext: "json",
    });
    cases.push(BenchCase {
        name: "synth/session.jsonl (500 lines)".to_owned(),
        lang: Lang::Jsonl,
        src: synth_jsonl(500),
        selector: "L200".to_owned(),
        ext: "jsonl",
    });
    cases.push(BenchCase {
        name: "synth/Tenants.razor (60 handlers)".to_owned(),
        lang: Lang::Razor,
        src: synth_razor(60),
        selector: "Refresh40Async".to_owned(),
        ext: "razor",
    });
    cases.push(BenchCase {
        name: "synth/Deploy.ps1 (50 functions)".to_owned(),
        lang: Lang::PowerShell,
        src: synth_powershell(50),
        selector: "Invoke-Step30".to_owned(),
        ext: "ps1",
    });

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = std::env::temp_dir().join(format!("prom_bench_{}_{nanos}", std::process::id()));
    fs::create_dir_all(&scratch).unwrap();

    let outline_opts = OutlineOptions::default();
    let slice_opts = SliceOptions::default();
    const RUNS: usize = 20;

    println!(
        "{:<44} {:>8} {:>8} {:>9} {:>10} {:>9}",
        "Fixture", "Raw tok", "Out tok", "Out+Slice", "Saved", "Med ms"
    );
    println!("{}", "-".repeat(94));

    let mut total_raw = 0usize;
    let mut total_out_slice = 0usize;

    for (idx, c) in cases.iter().enumerate() {
        let raw_tok = approx_tokens(&c.src);
        let temp_path = scratch.join(format!("case_{idx}.{}", c.ext));
        fs::write(&temp_path, c.src.as_bytes()).unwrap();
        let spec_str = format!("{}::{}", temp_path.display(), c.selector);
        let spec = parse_spec(&spec_str).unwrap();

        // Warmup
        let doc = outline_source(&c.name, &c.src, c.lang, &outline_opts);
        let out_txt = render_outline_text(&[doc], &outline_opts);
        let slice_res = execute_slices(std::slice::from_ref(&spec), &slice_opts).unwrap();
        let slice_txt = render_slice_text(&slice_res, &slice_opts);

        let mut timings = Vec::with_capacity(RUNS);
        for _ in 0..RUNS {
            let t0 = Instant::now();
            let d = outline_source(&c.name, &c.src, c.lang, &outline_opts);
            let _ = render_outline_text(&[d], &outline_opts);
            let sr = execute_slices(std::slice::from_ref(&spec), &slice_opts).unwrap();
            let _ = render_slice_text(&sr, &slice_opts);
            timings.push(t0.elapsed().as_micros());
        }

        let out_tok = approx_tokens(&out_txt);
        let combined_tok = out_tok + approx_tokens(&slice_txt);
        let saved_pct = if raw_tok > 0 {
            (1.0 - (combined_tok as f64 / raw_tok as f64)) * 100.0
        } else {
            0.0
        };
        let med_ms = median_us(timings) / 1000.0;
        total_raw += raw_tok;
        total_out_slice += combined_tok;

        println!(
            "{:<44} {:>8} {:>8} {:>9} {:>9.1}% {:>9.2}",
            c.name, raw_tok, out_tok, combined_tok, saved_pct, med_ms
        );
    }

    let overall = (1.0 - (total_out_slice as f64 / total_raw as f64)) * 100.0;
    println!("{}", "-".repeat(94));
    println!(
        "{:<44} {:>8} {:>8} {:>9} {:>9.1}%",
        "TOTAL (outline + 1 targeted slice)", total_raw, "-", total_out_slice, overall
    );

    println!("\n{:<44} {:>8} {:>8} {:>10} {:>9}", "Toolkit Subcommand", "Raw tok", "Kit tok", "Saved", "Med ms");
    println!("{}", "-".repeat(83));

    // 1. compact benchmark: noisy MSBuild + repeated errors + stacktrace log
    let mut msbuild_log = String::from("MSBuild version 17.10\n  Determining projects to restore...\n  All projects are up-to-date for restore.\n");
    for i in 0..120 {
        msbuild_log.push_str(&format!("  Project{i} -> /tmp/out/Project{i}.dll\n"));
        msbuild_log.push_str(&format!("src/Service{i}.cs(42,10): error CS0103: The name 'TenantCtx' does not exist in the current context [/tmp/App.csproj]\n"));
        msbuild_log.push_str(&format!("src/Handler{i}.cs(15,4): warning CS0168: Unused variable 'ex' [/tmp/App.csproj]\n"));
    }
    for _ in 0..8 {
        msbuild_log.push_str("   at System.Threading.Tasks.Task.Execute()\n   at Microsoft.AspNetCore.Mvc.Controller.Invoke()\n   at Xunit.Sdk.TestInvoker.Invoke()\n");
    }
    let c_opts = CompactOptions {
        mode: CompactMode::Build,
        allow_spillover: false,
        ..CompactOptions::default()
    };
    let c_raw = approx_tokens(&msbuild_log);
    let c_out = render_compact_text(&compact_text(&msbuild_log, Some(1), &c_opts), c_opts.max_tokens);
    let mut c_timings = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let t0 = Instant::now();
        let r = compact_text(&msbuild_log, Some(1), &c_opts);
        let _ = render_compact_text(&r, c_opts.max_tokens);
        c_timings.push(t0.elapsed().as_micros());
    }
    let c_tok = approx_tokens(&c_out);
    println!(
        "{:<44} {:>8} {:>8} {:>9.1}% {:>9.2}",
        "compact (120 errors+warnings+restore)",
        c_raw,
        c_tok,
        (1.0 - c_tok as f64 / c_raw as f64) * 100.0,
        median_us(c_timings) / 1000.0
    );

    // 2. search benchmark on core/src with --symbols vs raw matching file lines
    let s_opts = SearchOptions {
        pattern: "outline_source".to_owned(),
        paths: vec![root.join("core/src")],
        annotate_symbols: true,
        ..SearchOptions::default()
    };
    let s_res = execute_search(&s_opts).unwrap();
    let s_out = render_search_text(&s_res, &s_opts);
    let mut s_timings = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let t0 = Instant::now();
        let r = execute_search(&s_opts).unwrap();
        let _ = render_search_text(&r, &s_opts);
        s_timings.push(t0.elapsed().as_micros());
    }
    let s_raw: usize = s_res
        .files
        .iter()
        .filter_map(|f| fs::read_to_string(&f.path).ok())
        .map(|txt| approx_tokens(&txt))
        .sum();
    let s_tok = approx_tokens(&s_out);
    println!(
        "{:<44} {:>8} {:>8} {:>9.1}% {:>9.2}",
        "search --symbols (core/src)",
        s_raw,
        s_tok,
        (1.0 - s_tok as f64 / s_raw.max(1) as f64) * 100.0,
        median_us(s_timings) / 1000.0
    );

    // 3. map benchmark on core/src with --symbols vs reading files
    let m_opts = MapOptions {
        root: root.join("core"),
        include_symbols: true,
        ..MapOptions::default()
    };
    let m_res = execute_map(&m_opts).unwrap();
    let m_out = render_map_text(&m_res, m_opts.max_tokens);
    let mut m_timings = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let t0 = Instant::now();
        let r = execute_map(&m_opts).unwrap();
        let _ = render_map_text(&r, m_opts.max_tokens);
        m_timings.push(t0.elapsed().as_micros());
    }
    let m_tok = approx_tokens(&m_out);
    println!(
        "{:<44} {:>8} {:>8} {:>9.1}% {:>9.2}",
        "map --symbols (core/)",
        total_raw,
        m_tok,
        (1.0 - m_tok as f64 / total_raw.max(1) as f64) * 100.0,
        median_us(m_timings) / 1000.0
    );

    // 4. diff benchmark on temp repo with real edit + large lockfile noise
    let git_dir = scratch.join("diff_repo");
    fs::create_dir_all(&git_dir).unwrap();
    let run_git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(&git_dir)
            .args(args)
            .status()
            .unwrap();
    };
    run_git(&["init"]);
    run_git(&["config", "user.email", "b@example.com"]);
    run_git(&["config", "user.name", "Bench"]);
    fs::write(git_dir.join("lib.rs"), "pub fn calc(x: i32) -> i32 {\n    x + 1\n}\n").unwrap();
    let lock_v1: String = (0..600).map(|i| format!("pkg_{i} = \"1.0.0\"\n")).collect();
    fs::write(git_dir.join("Cargo.lock"), &lock_v1).unwrap();
    run_git(&["add", "-A"]);
    run_git(&["commit", "-m", "init"]);
    fs::write(git_dir.join("lib.rs"), "pub fn calc(x: i32) -> i32 {\n    x * 2\n}\n").unwrap();
    let lock_v2: String = (0..600).map(|i| format!("pkg_{i} = \"1.0.1\"\n")).collect();
    fs::write(git_dir.join("Cargo.lock"), &lock_v2).unwrap();

    let raw_git = Command::new("git")
        .arg("-C")
        .arg(&git_dir)
        .args(["diff", "HEAD"])
        .output()
        .unwrap();
    let d_raw = approx_tokens(&String::from_utf8_lossy(&raw_git.stdout));
    let d_opts = DiffOptions {
        root: git_dir,
        mode: DiffMode::Worktree,
        ..DiffOptions::default()
    };
    let d_res = execute_diff(&d_opts).unwrap();
    let d_out = render_diff_text(&d_res, d_opts.max_tokens);
    let mut d_timings = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let t0 = Instant::now();
        let r = execute_diff(&d_opts).unwrap();
        let _ = render_diff_text(&r, d_opts.max_tokens);
        d_timings.push(t0.elapsed().as_micros());
    }
    let d_tok = approx_tokens(&d_out);
    println!(
        "{:<44} {:>8} {:>8} {:>9.1}% {:>9.2}",
        "diff (code + 600L lockfile noise)",
        d_raw,
        d_tok,
        (1.0 - d_tok as f64 / d_raw.max(1) as f64) * 100.0,
        median_us(d_timings) / 1000.0
    );

    let _ = fs::remove_dir_all(&scratch);
}
