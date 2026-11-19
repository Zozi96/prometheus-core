//! Switch installed Factory Droid model pins between standard (`off`) and fallback (`on`) modes.
//!
//! Reads the mode tables from `droid-modes.json` (`--config <path>`, else
//! `<home>/.agents/prometheus/droid-modes.json`, else `<exe_dir>/droid-modes.json`),
//! validates all target files before writing, and atomically replaces each droid
//! profile and `settings.json` while preserving symlinks and permissions.

use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Deserialize)]
pub struct ModeTable {
    pub droids: BTreeMap<String, [String; 2]>,
    pub session: Map<String, Value>,
    pub subagents: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
pub struct ModesConfig {
    pub off: ModeTable,
    pub on: ModeTable,
}

pub fn default_home() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        if let Some(val) = std::env::var_os("USERPROFILE") {
            if !val.is_empty() {
                return Ok(PathBuf::from(val));
            }
        }
    }
    if let Some(val) = std::env::var_os("HOME") {
        if !val.is_empty() {
            return Ok(PathBuf::from(val));
        }
    }
    #[cfg(not(windows))]
    if let Some(val) = std::env::var_os("USERPROFILE") {
        if !val.is_empty() {
            return Ok(PathBuf::from(val));
        }
    }
    Err("HOME is not set".to_string())
}

pub fn resolve_config_path(explicit: Option<&Path>, home: &Path) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    let installed = home
        .join(".agents")
        .join("prometheus")
        .join("droid-modes.json");
    if installed.is_file() {
        return Ok(installed);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("droid-modes.json");
            if sibling.is_file() {
                return Ok(sibling);
            }
        }
    }
    Err(format!(
        "mode table not found at {}; run ./install.sh or pass --config",
        installed.display()
    ))
}

pub fn load_modes(config_path: &Path) -> Result<ModesConfig, String> {
    let raw = fs::read_to_string(config_path)
        .map_err(|e| format!("cannot read {}: {e}", config_path.display()))?;
    let cfg: ModesConfig = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid mode table {}: {e}", config_path.display()))?;
    for (mode_name, table) in [("off", &cfg.off), ("on", &cfg.on)] {
        if table
            .session
            .get("model")
            .is_none_or(|v| v.as_str().is_none_or(str::is_empty))
        {
            return Err(format!(
                "{}: {mode_name}.session.model must be a non-empty string",
                config_path.display()
            ));
        }
        for key in ["lightModel", "lightReasoningEffort"] {
            if table
                .subagents
                .get(key)
                .is_none_or(|v| v.as_str().is_none_or(str::is_empty))
            {
                return Err(format!(
                    "{}: {mode_name}.subagents.{key} must be a non-empty string",
                    config_path.display()
                ));
            }
        }
    }
    Ok(cfg)
}

/// Return droid text with frontmatter `model:` and `reasoningEffort:` set; body is untouched.
pub fn repin(text: &str, model: &str, effort: &str) -> Result<String, String> {
    let parts: Vec<&str> = text.splitn(3, "---").collect();
    if parts.len() != 3 || !parts[0].trim().is_empty() {
        return Err("missing frontmatter".to_string());
    }
    let newline = if parts[1].contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines: Vec<String> = parts[1]
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .filter(|line| !line.starts_with("reasoningEffort:"))
        .map(ToString::to_string)
        .collect();
    let Some(index) = lines.iter().position(|line| line.starts_with("model:")) else {
        return Err("frontmatter has no model:".to_string());
    };
    lines[index] = format!("model: {model}");
    lines.insert(index + 1, format!("reasoningEffort: {effort}"));
    Ok(format!("---{}---{}", lines.join(newline), parts[2]))
}

fn is_broken_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink() && !path.exists())
        .unwrap_or(false)
}

fn write_atomic_preserving(path: &Path, content: &str) -> Result<(), String> {
    let target = match fs::canonicalize(path) {
        Ok(resolved) => resolved,
        Err(_) => match (path.parent().and_then(|p| fs::canonicalize(p).ok()), path.file_name()) {
            (Some(parent), Some(name)) => parent.join(name),
            _ => path.to_path_buf(),
        },
    };
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(&target)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o600)
    };
    let parent = target
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", target.display()))?;
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".{name}.{}.{seq}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|e| format!("cannot create temp file for {}: {e}", target.display()))?;
    if let Err(err) = file.write_all(content.as_bytes()).and_then(|()| file.flush()) {
        drop(file);
        let _ = fs::remove_file(&tmp);
        return Err(format!("cannot write {}: {err}", target.display()));
    }
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) = fs::set_permissions(&tmp, fs::Permissions::from_mode(mode)) {
            let _ = fs::remove_file(&tmp);
            return Err(format!("cannot set permissions on {}: {err}", target.display()));
        }
    }
    if let Err(err) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("cannot replace {}: {err}", target.display()));
    }
    Ok(())
}

fn is_safe_droid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

pub fn apply_mode(mode: &str, home: &Path, config_path: &Path) -> Result<String, String> {
    let modes = load_modes(config_path)?;
    let table = match mode {
        "on" => &modes.on,
        "off" => &modes.off,
        _ => return Err(format!("unknown mode `{mode}`")),
    };
    let factory = home.join(".factory");
    let settings_path = factory.join("settings.json");
    if is_broken_symlink(&settings_path) {
        return Err(format!(
            "{} is a broken symlink; restore its target before switching modes",
            settings_path.display()
        ));
    }

    let mut writes: Vec<(PathBuf, String)> = Vec::with_capacity(table.droids.len() + 1);
    for (name, [model, effort]) in &table.droids {
        if !is_safe_droid_name(name) {
            return Err(format!("invalid droid name `{name}`"));
        }
        let path = factory.join("droids").join(format!("{name}.md"));
        if is_broken_symlink(&path) {
            return Err(format!(
                "{} is a broken symlink; restore its target before switching modes",
                path.display()
            ));
        }
        if !path.is_file() {
            return Err(format!(
                "{} is missing; run ./install.sh --droid first",
                path.display()
            ));
        }
        let current = fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let updated = repin(&current, model, effort)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        writes.push((path, updated));
    }

    let raw = if settings_path.exists() {
        fs::read_to_string(&settings_path)
            .map_err(|e| format!("cannot read {}: {e}", settings_path.display()))?
    } else {
        "{}\n".to_string()
    };
    let mut root: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("{} is invalid JSON: {e}", settings_path.display()))?;
    let Some(settings) = root.as_object_mut() else {
        return Err(format!("{} is not a JSON object", settings_path.display()));
    };

    for (key, updates) in [
        ("sessionDefaultSettings", &table.session),
        ("subagentModelSettings", &table.subagents),
    ] {
        if let Some(existing) = settings.get(key) {
            if !existing.is_object() {
                return Err(format!("{}: {key} is not an object", settings_path.display()));
            }
        } else {
            settings.insert(key.to_string(), Value::Object(Map::new()));
        }
        let target_map = settings
            .get_mut(key)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| format!("{}: {key} is not an object", settings_path.display()))?;
        for (k, v) in updates {
            target_map.insert(k.clone(), v.clone());
        }
    }

    let mut rendered = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("cannot serialize settings: {e}"))?;
    if raw.ends_with('\n') {
        rendered.push('\n');
    }
    writes.push((settings_path.clone(), rendered));

    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    for (path, text) in &writes {
        write_atomic_preserving(path, text)?;
    }

    let pins = table
        .droids
        .iter()
        .map(|(name, [model, effort])| format!("{name} {model} {effort}"))
        .collect::<Vec<_>>()
        .join(", ");
    let light_model = table
        .subagents
        .get("lightModel")
        .and_then(Value::as_str)
        .unwrap_or("");
    let light_effort = table
        .subagents
        .get("lightReasoningEffort")
        .and_then(Value::as_str)
        .unwrap_or("");
    let session_model = table
        .session
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("");
    Ok(format!(
        "Droid core mode {mode}: {pins}; complexity light {light_model} {light_effort}; \
         new sessions start on {session_model}. Switch the open session with /model {session_model}."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "prom_droid_ut_{tag}_{}_{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_sample_config(dir: &Path) -> PathBuf {
        let cfg = serde_json::json!({
            "off": {
                "droids": {
                    "argus": ["gemini-4-carbon", "medium"],
                    "hephaestus": ["gemini-4-hydrogen", "medium"]
                },
                "session": {"model": "gpt-6.2-sol", "reasoningEffort": "medium"},
                "subagents": {
                    "lightModel": "deepseek-v4.1-flash-1017",
                    "lightReasoningEffort": "low"
                }
            },
            "on": {
                "droids": {
                    "argus": ["glm-5.3", "high"],
                    "hephaestus": ["deepseek-v4.1-flash-1017", "high"]
                },
                "session": {"model": "kimi-k3.1-pro", "reasoningEffort": "medium"},
                "subagents": {
                    "lightModel": "deepseek-v4.1-flash-1017",
                    "lightReasoningEffort": "low"
                }
            }
        });
        let path = dir.join("droid-modes.json");
        fs::write(&path, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
        path
    }

    fn seed_droids(home: &Path, crlf: bool) {
        let droids = home.join(".factory").join("droids");
        fs::create_dir_all(&droids).unwrap();
        for (name, model, effort) in [
            ("argus", "gemini-4-carbon", "medium"),
            ("hephaestus", "model-inherit", "medium"),
        ] {
            let mut text = format!(
                "---\nname: {name}\nmodel: {model}\nreasoningEffort: {effort}\n---\nBody for {name}.\n"
            );
            if crlf {
                text = text.replace('\n', "\r\n");
            }
            fs::write(droids.join(format!("{name}.md")), text).unwrap();
        }
    }

    #[test]
    fn round_trip_preserves_bodies_crlf_and_other_settings() {
        let tmp = TempDir::new("rt");
        let cfg = write_sample_config(&tmp.0);
        seed_droids(&tmp.0, true);
        let settings = tmp.0.join(".factory").join("settings.json");
        fs::write(
            &settings,
            "{\n  \"logoAnimation\": \"off\",\n  \"sessionDefaultSettings\": {\"autonomyMode\": \"auto-high\"}\n}\n",
        )
        .unwrap();

        let msg = apply_mode("on", &tmp.0, &cfg).unwrap();
        assert!(msg.contains("/model kimi-k3.1-pro"));

        let argus = fs::read_to_string(tmp.0.join(".factory/droids/argus.md")).unwrap();
        assert!(argus.starts_with("---\r\nname: argus\r\nmodel: glm-5.3\r\nreasoningEffort: high\r\n---\r\nBody for argus.\r\n"));

        let parsed: Value = serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!("off", parsed["logoAnimation"]);
        assert_eq!("auto-high", parsed["sessionDefaultSettings"]["autonomyMode"]);
        assert_eq!("kimi-k3.1-pro", parsed["sessionDefaultSettings"]["model"]);

        apply_mode("off", &tmp.0, &cfg).unwrap();
        let heph = fs::read_to_string(tmp.0.join(".factory/droids/hephaestus.md")).unwrap();
        assert!(heph.contains("model: gemini-4-hydrogen\r\nreasoningEffort: medium\r\n"));
    }

    #[test]
    fn missing_droid_aborts_before_any_write() {
        let tmp = TempDir::new("missing");
        let cfg = write_sample_config(&tmp.0);
        let droids = tmp.0.join(".factory").join("droids");
        fs::create_dir_all(&droids).unwrap();
        fs::write(
            droids.join("argus.md"),
            "---\nname: argus\nmodel: gemini-4-carbon\nreasoningEffort: medium\n---\nBody\n",
        )
        .unwrap();
        let settings = tmp.0.join(".factory").join("settings.json");
        fs::write(&settings, "{\"keep\": 1}\n").unwrap();

        let err = apply_mode("on", &tmp.0, &cfg).unwrap_err();
        assert!(err.contains("install.sh --droid"));
        assert_eq!("{\"keep\": 1}\n", fs::read_to_string(&settings).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn preserves_symlinks_permissions_and_refuses_broken_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let tmp = TempDir::new("sym");
        let cfg = write_sample_config(&tmp.0);
        let real = tmp.0.join("dotfiles");
        fs::create_dir_all(&real).unwrap();
        let droids = tmp.0.join(".factory").join("droids");
        fs::create_dir_all(&droids).unwrap();

        for name in ["argus", "hephaestus"] {
            let real_f = real.join(format!("{name}.md"));
            fs::write(
                &real_f,
                format!("---\nname: {name}\nmodel: x\nreasoningEffort: low\n---\nBody\n"),
            )
            .unwrap();
            fs::set_permissions(&real_f, fs::Permissions::from_mode(0o644)).unwrap();
            symlink(&real_f, droids.join(format!("{name}.md"))).unwrap();
        }
        let real_settings = real.join("settings.json");
        fs::write(&real_settings, "{\"logoAnimation\": \"off\"}\n").unwrap();
        fs::set_permissions(&real_settings, fs::Permissions::from_mode(0o644)).unwrap();
        let settings_link = tmp.0.join(".factory").join("settings.json");
        symlink(&real_settings, &settings_link).unwrap();

        apply_mode("on", &tmp.0, &cfg).unwrap();
        assert!(fs::symlink_metadata(&settings_link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            0o644,
            fs::metadata(&real_settings).unwrap().permissions().mode() & 0o777
        );
        assert_eq!(
            0o644,
            fs::metadata(real.join("argus.md"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        );

        // Broken symlink aborts without modifying droids.
        fs::remove_file(&real_settings).unwrap();
        let before_argus = fs::read_to_string(real.join("argus.md")).unwrap();
        let err = apply_mode("off", &tmp.0, &cfg).unwrap_err();
        assert!(err.contains("broken symlink"));
        assert_eq!(before_argus, fs::read_to_string(real.join("argus.md")).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn new_settings_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new("priv");
        let cfg = write_sample_config(&tmp.0);
        seed_droids(&tmp.0, false);
        apply_mode("on", &tmp.0, &cfg).unwrap();
        let mode = fs::metadata(tmp.0.join(".factory/settings.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(0, mode & 0o077);
    }

    #[test]
    fn rejects_path_traversal_droid_name() {
        let tmp = TempDir::new("bad_name");
        let bad_cfg = tmp.0.join("droid-modes.json");
        fs::write(
            &bad_cfg,
            r#"{
  "off": {
    "droids": { "../evil": ["x", "low"] },
    "session": { "model": "a", "reasoningEffort": "medium" },
    "subagents": {
      "lightModel": "b", "lightReasoningEffort": "low",
      "mediumModel": "c", "mediumReasoningEffort": "medium",
      "heavyModel": "d", "heavyReasoningEffort": "high"
    }
  },
  "on": {
    "droids": { "../evil": ["y", "high"] },
    "session": { "model": "e", "reasoningEffort": "medium" },
    "subagents": {
      "lightModel": "f", "lightReasoningEffort": "low",
      "mediumModel": "g", "mediumReasoningEffort": "medium",
      "heavyModel": "h", "heavyReasoningEffort": "high"
    }
  }
}"#,
        )
        .unwrap();
        let err = apply_mode("on", &tmp.0, &bad_cfg).unwrap_err();
        assert!(err.contains("invalid droid name"), "unexpected error: {err}");
    }
}
