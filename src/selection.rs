//! Selection as a pure library function (ADR-0017, ticket #96).
//!
//! The Widening ladder that chooses a Check run's command lives here, not
//! in the `prometheus-check` binary's `main`: Tree scan facts go in as
//! typed values and a [`SelectionOutcome`] comes out. The function does
//! no I/O and never exits the process; "no test command is known" is a
//! returned value (Validation pending, GLOSSARY), not a process exit.
//! The level is an enum and every rung of the ladder is handled by name
//! — there is no catch-all rung. Missing or unusable impact facts widen
//! to the Full suite with a recorded reason, carried by the typed
//! [`ImpactFacts::Unavailable`] value instead of a hand-written JSON
//! document standing in for the impact computation.
//!
//! Vocabulary follows GLOSSARY.md: Selection, Widening, Tree scan,
//! Declared input.

use serde::Deserialize;

use crate::check::{
    dotnet_pick, mixed_plan, python_full, python_module, python_targeted, Config, DotnetPick,
    MixedPlan,
};

/// The level a Selection chooses: a Targeted check, a module check, or
/// the Full suite. Handled by name everywhere; there is no catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Targeted,
    Module,
    Full,
}

impl Level {
    /// The name the runner prints and records on a Green receipt.
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Targeted => "targeted",
            Level::Module => "module",
            Level::Full => "full",
        }
    }
}

/// The impact computation's Selection facts, deserialized from the
/// impact document's `selection` object. An impact document whose
/// selection does not deserialize into this shape is unusable, and the
/// caller treats a Scan cache entry carrying one as a miss.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ImpactSelection {
    pub level: Level,
    #[serde(default)]
    pub tests: Vec<String>,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub reasons: Vec<String>,
}

impl ImpactSelection {
    /// The typed Selection facts from an impact document, or `None`
    /// when the document's `selection` does not deserialize into them.
    pub fn from_document(document: &serde_json::Value) -> Option<ImpactSelection> {
        serde_json::from_value(document.get("selection")?.clone()).ok()
    }
}

/// Why impact facts are missing or unusable, recorded as a Widening
/// reason (ADR-0007 D4). The reason text is the one the runner has
/// always recorded for this widening.
pub const IMPACT_UNAVAILABLE_REASON: &str = "impact unavailable; widened to the full suite";

/// The impact side of a Tree scan, as a typed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImpactFacts {
    Available(ImpactSelection),
    Unavailable,
}

impl ImpactFacts {
    /// The effective Selection facts: unavailable impact widens to the
    /// Full suite with the recorded reason.
    fn effective(&self) -> ImpactSelection {
        match self {
            ImpactFacts::Available(selection) => selection.clone(),
            ImpactFacts::Unavailable => ImpactSelection {
                level: Level::Full,
                tests: Vec::new(),
                packages: Vec::new(),
                projects: Vec::new(),
                module: None,
                reasons: vec![IMPACT_UNAVAILABLE_REASON.to_owned()],
            },
        }
    }
}

/// A Python runtime the gathering step resolved: the interpreter path
/// (part of a Green receipt's identity, since it is part of the
/// launched command) and whether pytest is installed there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonRuntime {
    pub program: String,
    pub pytest: bool,
}

/// Root-layout facts the Full suite command is detected from. Gathered
/// once; Selection itself reads no filesystem.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LayoutFacts {
    pub cargo_toml: bool,
    pub csproj: bool,
    pub pyproject: bool,
    pub tests_dir: bool,
    pub package_json: bool,
}

/// The Tree scan facts Selection is a pure function of. Everything the
/// ladder needs arrives here as a typed value; the gathering step
/// (ticket #97) is the only place that reads the tree, git, or the
/// environment to produce them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeScanFacts {
    /// The sorted union of the Task delta and the Integration delta.
    pub changed: Vec<String>,
    /// The change class over `changed` (`crate::check::change_class`).
    pub change_class: String,
    /// Whether the delta attribution is certain: no Widening was
    /// recorded while computing the deltas.
    pub certain: bool,
    /// The Widening reasons the delta computation recorded.
    pub widen_reasons: Vec<String>,
    /// Deleted test files: a removed test cannot be selected, so their
    /// presence widens to the Full suite.
    pub deleted_tests: Vec<String>,
    /// The impact facts, typed.
    pub impact: ImpactFacts,
    /// The repository's declared `test_command`, if any.
    pub declared_test_command: Option<Vec<String>>,
    /// The resolved Python runtime, if one starts.
    pub python: Option<PythonRuntime>,
    /// The solution files at the repository root.
    pub root_solutions: Vec<String>,
    /// Root-layout facts for Full suite detection.
    pub layout: LayoutFacts,
}

/// A chosen Selection: the command, its level, and the Widening
/// reasons recorded along the ladder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub command: Vec<String>,
    pub level: Level,
    pub reasons: Vec<String>,
}

/// Why no checks are owed for this tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoChecksOwed {
    NoChanges,
    DocsOnly,
}

/// What Selection returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionOutcome {
    Selected(Selection),
    NoChecksOwed(NoChecksOwed),
    /// No test command is known: Validation pending. `print_reasons`
    /// preserves the one case where the runner has always printed the
    /// Widening reasons before the pending line (a multi-family
    /// selection with no declared command to cover it); the Full suite
    /// fallback prints only the pending line.
    NoCommandKnown {
        reasons: Vec<String>,
        print_reasons: bool,
    },
}

/// The Full suite command for these facts: the declared `test_command`
/// first, then one detected from the project layout.
fn full_command(facts: &TreeScanFacts) -> Option<Vec<String>> {
    if let Some(command) = &facts.declared_test_command {
        return Some(command.clone());
    }
    if facts.layout.cargo_toml {
        return Some(vec!["cargo".into(), "test".into(), "--workspace".into()]);
    }
    if !facts.root_solutions.is_empty() || facts.layout.csproj {
        return Some(vec!["dotnet".into(), "test".into()]);
    }
    if facts.layout.pyproject || facts.layout.tests_dir {
        let python = facts.python.as_ref()?;
        return Some(python_full(
            &python.program,
            python.pytest,
            facts.layout.tests_dir,
        ));
    }
    if facts.layout.package_json {
        return Some(vec!["npm".into(), "test".into()]);
    }
    None
}

/// The pure Selection function: Tree scan facts in, a Selection (or a
/// named non-selection outcome) out. No I/O, no process exit.
pub fn select(facts: &TreeScanFacts) -> SelectionOutcome {
    if facts.changed.is_empty() && facts.certain {
        return SelectionOutcome::NoChecksOwed(NoChecksOwed::NoChanges);
    }
    if facts.change_class == "docs-only" && facts.certain {
        return SelectionOutcome::NoChecksOwed(NoChecksOwed::DocsOnly);
    }

    let impact = facts.impact.effective();
    let mut level = impact.level;
    let mut reasons = impact.reasons.clone();
    if !facts.certain {
        level = Level::Full;
        reasons.extend(facts.widen_reasons.iter().cloned());
    }
    if !facts.deleted_tests.is_empty() {
        level = Level::Full;
        reasons.push(format!(
            "deleted test {}; widened to the full suite",
            facts.deleted_tests.join(", ")
        ));
    }

    // The Full suite fallback shared by every rung: a returned value
    // when no test command is known, never a process exit.
    let full = |reasons: Vec<String>| -> SelectionOutcome {
        match full_command(facts) {
            Some(command) => SelectionOutcome::Selected(Selection {
                command,
                level: Level::Full,
                reasons,
            }),
            None => SelectionOutcome::NoCommandKnown {
                reasons,
                print_reasons: false,
            },
        }
    };

    match level {
        Level::Targeted => {
            let config = Config {
                test_command: facts.declared_test_command.clone(),
                ..Config::default()
            };
            let families = crate::check::selection_families(
                &impact.tests,
                &impact.packages,
                &impact.projects,
                impact.module.as_deref(),
            );
            match mixed_plan(&families, &config) {
                MixedPlan::Declared(command, reason) => {
                    reasons.push(reason);
                    SelectionOutcome::Selected(Selection {
                        command,
                        level: Level::Full,
                        reasons,
                    })
                }
                MixedPlan::Pending(reason) => {
                    reasons.push(reason);
                    SelectionOutcome::NoCommandKnown {
                        reasons,
                        print_reasons: true,
                    }
                }
                MixedPlan::Single => {
                    if !impact.packages.is_empty() {
                        let mut command = vec!["cargo".to_owned(), "test".to_owned()];
                        for package in &impact.packages {
                            command.push("-p".to_owned());
                            command.push(package.clone());
                        }
                        SelectionOutcome::Selected(Selection {
                            command,
                            level: Level::Targeted,
                            reasons,
                        })
                    } else if !impact.projects.is_empty() {
                        match dotnet_pick(&impact.projects, &facts.root_solutions) {
                            DotnetPick::Project(command) => SelectionOutcome::Selected(Selection {
                                command,
                                level: Level::Targeted,
                                reasons,
                            }),
                            DotnetPick::Solution(command, reason) => {
                                reasons.push(reason);
                                SelectionOutcome::Selected(Selection {
                                    command,
                                    level: Level::Full,
                                    reasons,
                                })
                            }
                            DotnetPick::Widen(reason) => {
                                reasons.push(reason);
                                full(reasons)
                            }
                        }
                    } else if !impact.tests.is_empty()
                        && impact.tests.iter().all(|test| test.ends_with(".py"))
                    {
                        match &facts.python {
                            Some(python) => SelectionOutcome::Selected(Selection {
                                command: python_targeted(
                                    &python.program,
                                    python.pytest,
                                    &impact.tests,
                                ),
                                level: Level::Targeted,
                                reasons,
                            }),
                            None => {
                                reasons.push(
                                    "no Python interpreter found; widened to the full suite"
                                        .to_owned(),
                                );
                                full(reasons)
                            }
                        }
                    } else if let Some(module) = &impact.module {
                        match &facts.python {
                            Some(python) => SelectionOutcome::Selected(Selection {
                                command: python_module(&python.program, python.pytest, module),
                                level: Level::Targeted,
                                reasons,
                            }),
                            None => {
                                reasons.push(
                                    "no Python interpreter found; widened to the full suite"
                                        .to_owned(),
                                );
                                full(reasons)
                            }
                        }
                    } else {
                        reasons.push(
                            "targeted selection has no runnable command; widened to the full suite"
                                .to_owned(),
                        );
                        full(reasons)
                    }
                }
            }
        }
        Level::Module => match (&impact.module, &facts.python) {
            (Some(module), Some(python)) => SelectionOutcome::Selected(Selection {
                command: python_module(&python.program, python.pytest, module),
                level: Level::Module,
                reasons,
            }),
            _ => {
                reasons.push(
                    "module selection has no runnable Python; widened to the full suite".to_owned(),
                );
                full(reasons)
            }
        },
        Level::Full => full(reasons),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| part.to_string()).collect()
    }

    /// Facts for a certain, logic-class change whose impact selects
    /// nothing yet; each case fills in the rung it exercises.
    fn base_facts() -> TreeScanFacts {
        TreeScanFacts {
            changed: argv(&["src/lib.py"]),
            change_class: "logic".to_owned(),
            certain: true,
            widen_reasons: Vec::new(),
            deleted_tests: Vec::new(),
            impact: ImpactFacts::Available(ImpactSelection {
                level: Level::Full,
                tests: Vec::new(),
                packages: Vec::new(),
                projects: Vec::new(),
                module: None,
                reasons: Vec::new(),
            }),
            declared_test_command: None,
            python: Some(PythonRuntime {
                program: "python3".to_owned(),
                pytest: true,
            }),
            root_solutions: Vec::new(),
            layout: LayoutFacts::default(),
        }
    }

    fn impact(level: Level) -> ImpactFacts {
        ImpactFacts::Available(ImpactSelection {
            level,
            tests: Vec::new(),
            packages: Vec::new(),
            projects: Vec::new(),
            module: None,
            reasons: Vec::new(),
        })
    }

    fn selected(outcome: SelectionOutcome) -> Selection {
        match outcome {
            SelectionOutcome::Selected(selection) => selection,
            other => panic!("expected a selection, got {other:?}"),
        }
    }

    #[test]
    fn ladder_rungs_and_widening_reasons() {
        // (name, facts, expected command, expected level, expected reasons)
        type Case = (&'static str, TreeScanFacts, Vec<String>, Level, Vec<String>);
        let mut cases: Vec<Case> = Vec::new();

        // Targeted: cargo packages.
        let mut facts = base_facts();
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Targeted;
            selection.packages = argv(&["core", "kit"]);
        }
        cases.push((
            "targeted cargo packages",
            facts,
            argv(&["cargo", "test", "-p", "core", "-p", "kit"]),
            Level::Targeted,
            Vec::new(),
        ));

        // Targeted: a lone .NET project.
        let mut facts = base_facts();
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Targeted;
            selection.projects = argv(&["tests/App.Tests.csproj"]);
        }
        cases.push((
            "targeted dotnet project",
            facts,
            argv(&["dotnet", "test", "tests/App.Tests.csproj"]),
            Level::Targeted,
            Vec::new(),
        ));

        // Targeted: several .NET projects widen to the one root solution.
        let mut facts = base_facts();
        facts.root_solutions = argv(&["all.sln"]);
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Targeted;
            selection.projects = argv(&["a.csproj", "b.csproj"]);
        }
        cases.push((
            "dotnet projects widen to solution",
            facts,
            argv(&["dotnet", "test", "all.sln"]),
            Level::Full,
            argv(&["2 projects affected; widened to all.sln"]),
        ));

        // Targeted: several .NET projects and no single solution widen
        // to the Full suite (here the declared command).
        let mut facts = base_facts();
        facts.declared_test_command = Some(argv(&["make", "test"]));
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Targeted;
            selection.projects = argv(&["a.csproj", "b.csproj"]);
        }
        cases.push((
            "dotnet projects widen to full",
            facts,
            argv(&["make", "test"]),
            Level::Full,
            argv(&["2 projects affected and no single root solution; widened to the full suite"]),
        ));

        // Targeted: Python test files under pytest.
        let mut facts = base_facts();
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Targeted;
            selection.tests = argv(&["tests/test_calc.py"]);
        }
        cases.push((
            "targeted python tests",
            facts,
            argv(&["python3", "-m", "pytest", "-q", "tests/test_calc.py"]),
            Level::Targeted,
            Vec::new(),
        ));

        // Targeted: a module stands in when no test files are selected.
        let mut facts = base_facts();
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Targeted;
            selection.module = Some("tests/pkg".to_owned());
        }
        cases.push((
            "targeted python module",
            facts,
            argv(&["python3", "-m", "pytest", "-q", "tests/pkg"]),
            Level::Targeted,
            Vec::new(),
        ));

        // Targeted with no runnable command widens to the Full suite.
        let mut facts = base_facts();
        facts.layout.cargo_toml = true;
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Targeted;
        }
        cases.push((
            "targeted with no runnable command widens",
            facts,
            argv(&["cargo", "test", "--workspace"]),
            Level::Full,
            argv(&["targeted selection has no runnable command; widened to the full suite"]),
        ));

        // Targeted Python with no interpreter widens to the Full suite.
        let mut facts = base_facts();
        facts.python = None;
        facts.layout.cargo_toml = true;
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Targeted;
            selection.tests = argv(&["tests/test_calc.py"]);
        }
        cases.push((
            "targeted python without interpreter widens",
            facts,
            argv(&["cargo", "test", "--workspace"]),
            Level::Full,
            argv(&["no Python interpreter found; widened to the full suite"]),
        ));

        // Module: pytest over the module directory.
        let mut facts = base_facts();
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Module;
            selection.module = Some("tests/pkg".to_owned());
        }
        cases.push((
            "module",
            facts,
            argv(&["python3", "-m", "pytest", "-q", "tests/pkg"]),
            Level::Module,
            Vec::new(),
        ));

        // Module without a runnable Python widens to the Full suite.
        let mut facts = base_facts();
        facts.python = None;
        facts.layout.package_json = true;
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Module;
            selection.module = Some("tests/pkg".to_owned());
        }
        cases.push((
            "module without python widens",
            facts,
            argv(&["npm", "test"]),
            Level::Full,
            argv(&["module selection has no runnable Python; widened to the full suite"]),
        ));

        // Full: the impact rung itself.
        let mut facts = base_facts();
        facts.layout.pyproject = true;
        facts.layout.tests_dir = true;
        cases.push((
            "full python",
            facts,
            argv(&["python3", "-m", "pytest", "-q"]),
            Level::Full,
            Vec::new(),
        ));

        // Uncertain delta attribution widens any rung to the Full suite.
        let mut facts = base_facts();
        facts.certain = false;
        facts.widen_reasons = argv(&["working-tree status unavailable; widened to the full suite"]);
        facts.layout.cargo_toml = true;
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Targeted;
            selection.packages = argv(&["core"]);
        }
        cases.push((
            "uncertain deltas widen",
            facts,
            argv(&["cargo", "test", "--workspace"]),
            Level::Full,
            argv(&["working-tree status unavailable; widened to the full suite"]),
        ));

        // A deleted test widens to the Full suite.
        let mut facts = base_facts();
        facts.deleted_tests = argv(&["tests/test_gone.py"]);
        facts.layout.cargo_toml = true;
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Targeted;
            selection.packages = argv(&["core"]);
        }
        cases.push((
            "deleted test widens",
            facts,
            argv(&["cargo", "test", "--workspace"]),
            Level::Full,
            argv(&["deleted test tests/test_gone.py; widened to the full suite"]),
        ));

        // Unavailable impact facts widen with the recorded reason.
        let mut facts = base_facts();
        facts.impact = ImpactFacts::Unavailable;
        facts.layout.cargo_toml = true;
        cases.push((
            "impact unavailable widens",
            facts,
            argv(&["cargo", "test", "--workspace"]),
            Level::Full,
            argv(&[IMPACT_UNAVAILABLE_REASON]),
        ));

        // A multi-family selection runs the declared command as Full.
        let mut facts = base_facts();
        facts.declared_test_command = Some(argv(&["make", "test"]));
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Targeted;
            selection.tests = argv(&["tests/test_calc.py"]);
            selection.packages = argv(&["core"]);
        }
        cases.push((
            "mixed families use declared command",
            facts,
            argv(&["make", "test"]),
            Level::Full,
            argv(&[
                "selection spans several runner families (cargo, python); widened to the declared test_command",
            ]),
        ));

        for (name, facts, command, level, reasons) in cases {
            let selection = selected(select(&facts));
            assert_eq!(selection.command, command, "{name}");
            assert_eq!(selection.level, level, "{name}");
            assert_eq!(selection.reasons, reasons, "{name}");
        }
    }

    #[test]
    fn no_command_known_is_a_returned_value() {
        // Full rung, no declared command, empty layout: nothing to run.
        let facts = base_facts();
        match select(&facts) {
            SelectionOutcome::NoCommandKnown { print_reasons, .. } => assert!(!print_reasons),
            other => panic!("expected NoCommandKnown, got {other:?}"),
        }

        // A multi-family selection with no declared command: pending,
        // with the reasons printed first (the runner's standing shape).
        let mut facts = base_facts();
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Targeted;
            selection.tests = argv(&["tests/test_calc.py"]);
            selection.packages = argv(&["core"]);
        }
        match select(&facts) {
            SelectionOutcome::NoCommandKnown {
                reasons,
                print_reasons,
            } => {
                assert!(print_reasons);
                assert_eq!(
                    reasons,
                    argv(&[
                        "selection spans several runner families (cargo, python) and no test_command is declared",
                    ])
                );
            }
            other => panic!("expected NoCommandKnown, got {other:?}"),
        }

        // Module rung with no Python and no Full suite command either.
        let mut facts = base_facts();
        facts.python = None;
        facts.impact = impact(Level::Module);
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.module = Some("tests/pkg".to_owned());
        }
        match select(&facts) {
            SelectionOutcome::NoCommandKnown { reasons, .. } => assert_eq!(
                reasons,
                argv(&["module selection has no runnable Python; widened to the full suite"])
            ),
            other => panic!("expected NoCommandKnown, got {other:?}"),
        }
    }

    #[test]
    fn no_checks_owed_cases() {
        let mut facts = base_facts();
        facts.changed = Vec::new();
        assert_eq!(
            select(&facts),
            SelectionOutcome::NoChecksOwed(NoChecksOwed::NoChanges)
        );

        let mut facts = base_facts();
        facts.changed = argv(&["README.md"]);
        facts.change_class = "docs-only".to_owned();
        assert_eq!(
            select(&facts),
            SelectionOutcome::NoChecksOwed(NoChecksOwed::DocsOnly)
        );

        // The same trees with uncertain attribution owe the Full suite.
        let mut facts = base_facts();
        facts.changed = Vec::new();
        facts.certain = false;
        facts.widen_reasons = argv(&["working-tree status unavailable; widened to the full suite"]);
        facts.layout.cargo_toml = true;
        assert_eq!(selected(select(&facts)).level, Level::Full);
    }

    #[test]
    fn equal_facts_give_an_equal_selection() {
        let mut facts = base_facts();
        if let ImpactFacts::Available(selection) = &mut facts.impact {
            selection.level = Level::Targeted;
            selection.tests = argv(&["tests/test_calc.py"]);
        }
        assert_eq!(select(&facts), select(&facts));
    }

    #[test]
    fn impact_selection_deserializes_typed_facts_only() {
        let document = serde_json::json!({
            "selection": {
                "level": "targeted",
                "tests": ["tests/test_a.py"],
                "packages": [],
                "projects": [],
                "module": null,
                "reasons": ["recorded"],
            }
        });
        let parsed = ImpactSelection::from_document(&document).unwrap();
        assert_eq!(parsed.level, Level::Targeted);
        assert_eq!(parsed.tests, argv(&["tests/test_a.py"]));
        assert_eq!(parsed.reasons, argv(&["recorded"]));

        // A level that is not one of the enum's named rungs does not
        // deserialize: the facts are unusable, never a catch-all.
        let bogus = serde_json::json!({"selection": {"level": "everything"}});
        assert_eq!(ImpactSelection::from_document(&bogus), None);
        assert_eq!(
            ImpactSelection::from_document(&serde_json::Value::Null),
            None
        );
    }
}
