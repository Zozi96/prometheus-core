//! Declarative shell rewrite rule table.
//!
//! Every rewriteable command shape is one [`RewriteRule`] entry: head match,
//! flag grammar, `--` handling, operand safety, target builder, and the
//! measured `rtk` deferral posture. The small evaluator below interprets that
//! data; adding a rule does not require editing a second `rtk` table.

use crate::outline::Lang;
use std::path::{Path, PathBuf};

use super::{shell_split, try_shell_quote, ShellToken};

/// The `rtk` release whose observed compaction behavior backs the deferral
/// postures below (ADR-0013 D7).
pub const RTK_VERIFIED_VERSION: &str = "1.2.0";

/// One declarative shell rewrite rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewriteRule {
    pub id: &'static str,
    pub head: HeadSpec,
    pub parser: ParserSpec,
    pub target: TargetSpec,
    pub rtk: RtkSpec,
    pub expansion: ExpansionRule,
}

/// Executable and exact argv prefix a rule matches. The executable is compared
/// after basename/lowercase normalization, as shell commands commonly use
/// paths such as `./gradlew`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadSpec {
    pub commands: &'static [&'static str],
    pub argv_prefix: &'static [&'static str],
    /// Accept one leading `git -C <dir>` and `--no-pager` before `argv_prefix`.
    pub git_c_prefix: bool,
    /// When set, the first post-prefix token must/must not contain `:`.
    /// This splits otherwise identical git-show heads without falling through
    /// after a fail-closed parse.
    pub first_positional_colon: Option<bool>,
}

const fn head(commands: &'static [&'static str], argv_prefix: &'static [&'static str]) -> HeadSpec {
    HeadSpec {
        commands,
        argv_prefix,
        git_c_prefix: false,
        first_positional_colon: None,
    }
}

/// Argument parsing posture for a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserSpec {
    /// Do not interpret trailing arguments. The original argv is re-emitted
    /// after `--`, so flags and expansions keep their shell meaning.
    Verbatim,
    Structured(StructuredParserSpec),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuredParserSpec {
    pub flags: &'static [FlagSpec],
    /// Permit single-dash clusters made only of `FlagSpec::cluster` chars.
    pub short_clusters: bool,
    /// Accept attached numeric `-N` forms as this flag id.
    pub numeric_short_flag: Option<&'static str>,
    pub double_dash: DoubleDashSpec,
    pub positionals: PositionalSpec,
    /// File-dump rules require the file to be final; search/git rules do not.
    pub flags_after_positionals: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoubleDashSpec {
    Reject,
    /// `--` ends option parsing; following tokens are positional operands.
    Boundary,
    /// Accept and discard one initial `--`, then parse normally.
    OptionalPrefix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PositionalSpec {
    pub min: usize,
    pub max: Option<usize>,
    /// Maximum positional operands before `--`; with no `--` every positional
    /// counts as before. Used by `git diff`, where one leading token is a
    /// candidate base ref and later paths require the separator.
    pub max_before_separator: Option<usize>,
    pub before_separator: OperandRule,
    pub after_separator: OperandRule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperandRule {
    pub reject_expansion: bool,
    pub reject_empty: bool,
    pub reject_colon: bool,
    pub require_colon: bool,
}

const OPERAND_ANY: OperandRule = OperandRule {
    reject_expansion: false,
    reject_empty: false,
    reject_colon: false,
    require_colon: false,
};

const OPERAND_LITERAL: OperandRule = OperandRule {
    reject_expansion: true,
    reject_empty: false,
    reject_colon: false,
    require_colon: false,
};

const OPERAND_STRICT_REF: OperandRule = OperandRule {
    reject_expansion: true,
    reject_empty: true,
    reject_colon: true,
    require_colon: false,
};

const OPERAND_REV_PATH: OperandRule = OperandRule {
    reject_expansion: true,
    reject_empty: true,
    reject_colon: false,
    require_colon: true,
};

const NO_POSITIONALS: PositionalSpec = PositionalSpec {
    min: 0,
    max: Some(0),
    max_before_separator: None,
    before_separator: OPERAND_ANY,
    after_separator: OPERAND_ANY,
};

const fn literal_positionals(min: usize, max: Option<usize>) -> PositionalSpec {
    PositionalSpec {
        min,
        max,
        max_before_separator: None,
        before_separator: OPERAND_LITERAL,
        after_separator: OPERAND_LITERAL,
    }
}

/// One accepted flag spelling family. `exact` forms consume a following value
/// when `value` is set; `attached_prefixes` cover `--flag=value` and `-U5`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagSpec {
    pub id: &'static str,
    pub exact: &'static [&'static str],
    pub attached_prefixes: &'static [&'static str],
    pub cluster: Option<char>,
    pub value: Option<ValueSpec>,
    pub repeat: RepeatSpec,
    pub required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeatSpec {
    Once,
    Many,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueSpec {
    pub validation: ValueValidation,
    pub reject_empty: bool,
    pub reject_expansion: bool,
    pub reject_trailing_equals: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueValidation {
    Any,
    Usize,
    LangType,
    DumpCount { allow_plus: bool },
}

const VALUE_LITERAL: ValueSpec = ValueSpec {
    validation: ValueValidation::Any,
    reject_empty: true,
    reject_expansion: true,
    reject_trailing_equals: false,
};

const VALUE_VERBATIM: ValueSpec = ValueSpec {
    validation: ValueValidation::Any,
    reject_empty: true,
    reject_expansion: false,
    reject_trailing_equals: true,
};

const VALUE_USIZE: ValueSpec = ValueSpec {
    validation: ValueValidation::Usize,
    reject_empty: true,
    reject_expansion: true,
    reject_trailing_equals: false,
};

const VALUE_LANG: ValueSpec = ValueSpec {
    validation: ValueValidation::LangType,
    reject_empty: true,
    reject_expansion: true,
    reject_trailing_equals: false,
};

const fn bool_flag(
    id: &'static str,
    exact: &'static [&'static str],
    cluster: Option<char>,
) -> FlagSpec {
    FlagSpec {
        id,
        exact,
        attached_prefixes: &[],
        cluster,
        value: None,
        repeat: RepeatSpec::Many,
        required: false,
    }
}

const fn required_bool_flag(id: &'static str, exact: &'static [&'static str]) -> FlagSpec {
    FlagSpec {
        id,
        exact,
        attached_prefixes: &[],
        cluster: None,
        value: None,
        repeat: RepeatSpec::Once,
        required: true,
    }
}

const fn value_flag(
    id: &'static str,
    exact: &'static [&'static str],
    attached_prefixes: &'static [&'static str],
    value: ValueSpec,
    repeat: RepeatSpec,
) -> FlagSpec {
    FlagSpec {
        id,
        exact,
        attached_prefixes,
        cluster: None,
        value: Some(value),
        repeat,
        required: false,
    }
}

/// Which kit target the evaluator builds. Keeping this as data makes every
/// active rule enumerable without mirroring per-command implementation tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSpec {
    SliceSedRange,
    GitStatus,
    GitDiff,
    GitShow,
    GitShowBlob,
    SearchRg,
    SearchGrep,
    FileDump(FileDumpKind),
    CompactLog,
    CompactRunner { mode: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileDumpKind {
    Head,
    Tail,
    Whole,
}

/// Measured `rtk` coexistence posture for a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtkSpec {
    pub verified_version: &'static str,
    pub posture: RtkPosture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtkPosture {
    /// `rtk` leaves this form raw, so the kit rewrites it in either state.
    NeverDefer,
    /// `rtk` compacts this form; defer whenever an `rtk` hook is active.
    DeferWhenActive,
    Runner {
        standalone_claimed: bool,
        piped_claim: RtkPipedClaim,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtkPipedClaim {
    None,
    /// Literal `<command><ASCII space><subcommand>` spelling, matching the
    /// measured cargo/dotnet/go/mvn piped replies.
    CommandSubcommand,
    /// Literal exact prefixes such as `python -m pytest`, matched with the
    /// single-space boundaries observed in the `rtk` replies.
    LiteralPrefixes(&'static [&'static str]),
}

const RTK_NEVER: RtkSpec = RtkSpec {
    verified_version: RTK_VERIFIED_VERSION,
    posture: RtkPosture::NeverDefer,
};

const RTK_ACTIVE: RtkSpec = RtkSpec {
    verified_version: RTK_VERIFIED_VERSION,
    posture: RtkPosture::DeferWhenActive,
};

const fn runner_rtk(standalone_claimed: bool, piped_claim: RtkPipedClaim) -> RtkSpec {
    RtkSpec {
        verified_version: RTK_VERIFIED_VERSION,
        posture: RtkPosture::Runner {
            standalone_claimed,
            piped_claim,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpansionRule {
    /// Operands become kit arguments, so each structured operand/flag value
    /// declares whether expansions are refused.
    PerOperandLiteral,
    /// The original argv is re-emitted after `--` and expands exactly once.
    /// Piped truncation is stricter because the raw log must be recoverable.
    PreserveVerbatimOnce { reject_when_truncated: bool },
}

const EXPANSION_TRANSFORMED: ExpansionRule = ExpansionRule::PerOperandLiteral;
const EXPANSION_VERBATIM: ExpansionRule = ExpansionRule::PreserveVerbatimOnce {
    reject_when_truncated: true,
};

const GIT_STATUS_FLAGS: &[FlagSpec] = &[
    bool_flag("short", &["--short"], Some('s')),
    bool_flag("branch", &["--branch"], Some('b')),
];

const GIT_DIFF_FLAGS: &[FlagSpec] = &[
    bool_flag("staged", &["--staged", "--cached"], None),
    bool_flag("stat", &["--stat"], None),
    bool_flag("no-ext-diff", &["--no-ext-diff"], None),
    bool_flag("no-color", &["--no-color"], None),
    bool_flag("no-textconv", &["--no-textconv"], None),
    value_flag(
        "unified",
        &["--unified", "-U"],
        &["--unified=", "-U"],
        VALUE_USIZE,
        RepeatSpec::Many,
    ),
];

const GIT_SHOW_FLAGS: &[FlagSpec] = &[bool_flag("stat", &["--stat"], None)];

const RG_FLAGS: &[FlagSpec] = &[
    bool_flag("ignore-case", &["-i", "--ignore-case"], Some('i')),
    bool_flag("fixed-strings", &["-F", "--fixed-strings"], Some('F')),
    bool_flag("word-regexp", &["-w", "--word-regexp"], Some('w')),
    bool_flag("files-only", &["-l", "--files-with-matches"], Some('l')),
    bool_flag("hidden", &["--hidden"], None),
    bool_flag("no-ignore", &["--no-ignore"], None),
    value_flag(
        "glob",
        &["-g", "--glob"],
        &["--glob="],
        VALUE_LITERAL,
        RepeatSpec::Many,
    ),
    value_flag(
        "type",
        &["-t", "--type"],
        &["--type="],
        VALUE_LANG,
        RepeatSpec::Once,
    ),
];

const GREP_FLAGS: &[FlagSpec] = &[
    bool_flag("ignore-case", &["-i", "--ignore-case"], Some('i')),
    bool_flag("fixed-strings", &["-F", "--fixed-strings"], Some('F')),
    bool_flag("word-regexp", &["-w", "--word-regexp"], Some('w')),
    bool_flag("files-only", &["-l", "--files-with-matches"], Some('l')),
    bool_flag("extended-regexp", &["-E", "--extended-regexp"], Some('E')),
    bool_flag("line-number", &["-n", "--line-number"], Some('n')),
    bool_flag("with-filename", &["-H", "--with-filename"], Some('H')),
    bool_flag("no-filename", &["-h", "--no-filename"], Some('h')),
    bool_flag("recursive-r", &["-r"], Some('r')),
    bool_flag("recursive-R", &["-R", "--recursive"], Some('R')),
    bool_flag("no-messages", &["-s", "--no-messages"], Some('s')),
    value_flag(
        "pattern",
        &["-e", "--regexp"],
        &["--regexp="],
        VALUE_LITERAL,
        RepeatSpec::Once,
    ),
    value_flag(
        "include",
        &["--include"],
        &["--include="],
        VALUE_LITERAL,
        RepeatSpec::Many,
    ),
];

const HEAD_COUNT_VALUE: ValueSpec = ValueSpec {
    validation: ValueValidation::DumpCount { allow_plus: false },
    reject_empty: true,
    reject_expansion: true,
    reject_trailing_equals: false,
};

const TAIL_COUNT_VALUE: ValueSpec = ValueSpec {
    validation: ValueValidation::DumpCount { allow_plus: true },
    reject_empty: true,
    reject_expansion: true,
    reject_trailing_equals: false,
};

const HEAD_FLAGS: &[FlagSpec] = &[value_flag(
    "count",
    &["-n", "--lines"],
    &["--lines="],
    HEAD_COUNT_VALUE,
    RepeatSpec::Many,
)];

const TAIL_FLAGS: &[FlagSpec] = &[value_flag(
    "count",
    &["-n", "--lines"],
    &["--lines="],
    TAIL_COUNT_VALUE,
    RepeatSpec::Many,
)];

const GH_LOG_FLAGS: &[FlagSpec] = &[
    required_bool_flag("log", &["--log", "--log-failed"]),
    value_flag(
        "job",
        &["--job"],
        &["--job="],
        VALUE_VERBATIM,
        RepeatSpec::Many,
    ),
    value_flag(
        "attempt",
        &["--attempt"],
        &["--attempt="],
        VALUE_VERBATIM,
        RepeatSpec::Many,
    ),
    value_flag(
        "repo",
        &["-R", "--repo"],
        &["--repo="],
        VALUE_VERBATIM,
        RepeatSpec::Many,
    ),
];

const fn structured(
    flags: &'static [FlagSpec],
    double_dash: DoubleDashSpec,
    positionals: PositionalSpec,
) -> ParserSpec {
    ParserSpec::Structured(StructuredParserSpec {
        flags,
        short_clusters: false,
        numeric_short_flag: None,
        double_dash,
        positionals,
        flags_after_positionals: true,
    })
}

const fn structured_clusters(
    flags: &'static [FlagSpec],
    positionals: PositionalSpec,
) -> ParserSpec {
    ParserSpec::Structured(StructuredParserSpec {
        flags,
        short_clusters: true,
        numeric_short_flag: None,
        double_dash: DoubleDashSpec::Boundary,
        positionals,
        flags_after_positionals: true,
    })
}

const fn dump_parser(
    flags: &'static [FlagSpec],
    numeric_short_flag: Option<&'static str>,
) -> ParserSpec {
    ParserSpec::Structured(StructuredParserSpec {
        flags,
        short_clusters: false,
        numeric_short_flag,
        double_dash: DoubleDashSpec::OptionalPrefix,
        positionals: literal_positionals(1, Some(1)),
        flags_after_positionals: false,
    })
}

const GIT_DIFF_POSITIONALS: PositionalSpec = PositionalSpec {
    min: 0,
    max: None,
    max_before_separator: Some(1),
    before_separator: OPERAND_STRICT_REF,
    after_separator: OPERAND_LITERAL,
};

const GH_POSITIONALS: PositionalSpec = PositionalSpec {
    min: 0,
    max: Some(1),
    max_before_separator: None,
    before_separator: OPERAND_ANY,
    after_separator: OPERAND_ANY,
};

const VERBATIM_PARSER: ParserSpec = ParserSpec::Verbatim;

const fn runner_rule(
    id: &'static str,
    commands: &'static [&'static str],
    argv_prefix: &'static [&'static str],
    mode: &'static str,
    rtk: RtkSpec,
) -> RewriteRule {
    RewriteRule {
        id,
        head: head(commands, argv_prefix),
        parser: VERBATIM_PARSER,
        target: TargetSpec::CompactRunner { mode },
        rtk,
        expansion: EXPANSION_VERBATIM,
    }
}

/// Every active shell rewrite. Rule order is not overlapping: the first head
/// match owns the command and its fail-closed parse result.
static REWRITE_RULES: &[RewriteRule] = &[
    RewriteRule {
        id: "sed-line-range",
        head: head(&["sed"], &["-n"]),
        parser: structured(&[], DoubleDashSpec::Reject, literal_positionals(2, Some(2))),
        target: TargetSpec::SliceSedRange,
        rtk: RTK_NEVER,
        expansion: EXPANSION_TRANSFORMED,
    },
    RewriteRule {
        id: "git-status",
        head: HeadSpec {
            commands: &["git"],
            argv_prefix: &["status"],
            git_c_prefix: true,
            first_positional_colon: None,
        },
        parser: ParserSpec::Structured(StructuredParserSpec {
            flags: GIT_STATUS_FLAGS,
            short_clusters: true,
            numeric_short_flag: None,
            double_dash: DoubleDashSpec::Reject,
            positionals: NO_POSITIONALS,
            flags_after_positionals: true,
        }),
        target: TargetSpec::GitStatus,
        rtk: RTK_ACTIVE,
        expansion: EXPANSION_TRANSFORMED,
    },
    RewriteRule {
        id: "git-diff",
        head: HeadSpec {
            commands: &["git"],
            argv_prefix: &["diff"],
            git_c_prefix: true,
            first_positional_colon: None,
        },
        parser: structured(
            GIT_DIFF_FLAGS,
            DoubleDashSpec::Boundary,
            GIT_DIFF_POSITIONALS,
        ),
        target: TargetSpec::GitDiff,
        rtk: RTK_ACTIVE,
        expansion: EXPANSION_TRANSFORMED,
    },
    RewriteRule {
        id: "git-show-blob",
        head: HeadSpec {
            commands: &["git"],
            argv_prefix: &["show"],
            git_c_prefix: true,
            first_positional_colon: Some(true),
        },
        parser: structured(&[], DoubleDashSpec::Reject, {
            PositionalSpec {
                min: 1,
                max: Some(1),
                max_before_separator: None,
                before_separator: OPERAND_REV_PATH,
                after_separator: OPERAND_REV_PATH,
            }
        }),
        target: TargetSpec::GitShowBlob,
        rtk: RTK_NEVER,
        expansion: EXPANSION_TRANSFORMED,
    },
    RewriteRule {
        id: "git-show-commit",
        head: HeadSpec {
            commands: &["git"],
            argv_prefix: &["show"],
            git_c_prefix: true,
            first_positional_colon: None,
        },
        parser: structured(GIT_SHOW_FLAGS, DoubleDashSpec::Reject, {
            PositionalSpec {
                min: 1,
                max: Some(1),
                max_before_separator: None,
                before_separator: OPERAND_STRICT_REF,
                after_separator: OPERAND_STRICT_REF,
            }
        }),
        target: TargetSpec::GitShow,
        rtk: RTK_NEVER,
        expansion: EXPANSION_TRANSFORMED,
    },
    RewriteRule {
        id: "ripgrep-search",
        head: head(&["rg"], &[]),
        parser: structured_clusters(RG_FLAGS, literal_positionals(1, None)),
        target: TargetSpec::SearchRg,
        rtk: RTK_ACTIVE,
        expansion: EXPANSION_TRANSFORMED,
    },
    RewriteRule {
        id: "grep-search",
        head: head(&["grep"], &[]),
        parser: structured_clusters(GREP_FLAGS, literal_positionals(1, None)),
        target: TargetSpec::SearchGrep,
        rtk: RTK_NEVER,
        expansion: EXPANSION_TRANSFORMED,
    },
    RewriteRule {
        id: "head-file-dump",
        head: head(&["head"], &[]),
        parser: dump_parser(HEAD_FLAGS, Some("count")),
        target: TargetSpec::FileDump(FileDumpKind::Head),
        rtk: RTK_NEVER,
        expansion: EXPANSION_TRANSFORMED,
    },
    RewriteRule {
        id: "tail-file-dump",
        head: head(&["tail"], &[]),
        parser: dump_parser(TAIL_FLAGS, Some("count")),
        target: TargetSpec::FileDump(FileDumpKind::Tail),
        rtk: RTK_NEVER,
        expansion: EXPANSION_TRANSFORMED,
    },
    RewriteRule {
        id: "cat-file-dump",
        head: head(&["cat"], &[]),
        parser: dump_parser(&[], None),
        target: TargetSpec::FileDump(FileDumpKind::Whole),
        rtk: RTK_NEVER,
        expansion: EXPANSION_TRANSFORMED,
    },
    RewriteRule {
        id: "nl-file-dump",
        head: head(&["nl"], &[]),
        parser: dump_parser(&[], None),
        target: TargetSpec::FileDump(FileDumpKind::Whole),
        rtk: RTK_NEVER,
        expansion: EXPANSION_TRANSFORMED,
    },
    RewriteRule {
        id: "gh-run-view-log",
        head: head(&["gh"], &["run", "view"]),
        parser: structured(GH_LOG_FLAGS, DoubleDashSpec::Reject, GH_POSITIONALS),
        target: TargetSpec::CompactLog,
        rtk: RTK_NEVER,
        expansion: EXPANSION_VERBATIM,
    },
    runner_rule(
        "runner-dotnet-test",
        &["dotnet"],
        &["test"],
        "test",
        runner_rtk(false, RtkPipedClaim::None),
    ),
    runner_rule(
        "runner-dotnet-restore",
        &["dotnet"],
        &["restore"],
        "build",
        runner_rtk(false, RtkPipedClaim::CommandSubcommand),
    ),
    runner_rule(
        "runner-dotnet-format",
        &["dotnet"],
        &["format"],
        "build",
        runner_rtk(false, RtkPipedClaim::None),
    ),
    runner_rule(
        "runner-dotnet-build",
        &["dotnet"],
        &["build"],
        "build",
        runner_rtk(true, RtkPipedClaim::CommandSubcommand),
    ),
    runner_rule(
        "runner-msbuild",
        &["msbuild", "msbuild.exe"],
        &[],
        "build",
        runner_rtk(false, RtkPipedClaim::None),
    ),
    runner_rule(
        "runner-python-unittest",
        &["python", "python3"],
        &["-m", "unittest"],
        "test",
        runner_rtk(false, RtkPipedClaim::None),
    ),
    runner_rule(
        "runner-python-pytest",
        &["python", "python3"],
        &["-m", "pytest"],
        "test",
        runner_rtk(
            true,
            RtkPipedClaim::LiteralPrefixes(&["python -m pytest", "python3 -m pytest"]),
        ),
    ),
    runner_rule(
        "runner-npm-test",
        &["npm"],
        &["test"],
        "test",
        runner_rtk(false, RtkPipedClaim::None),
    ),
    runner_rule(
        "runner-npm-run-test",
        &["npm"],
        &["run", "test"],
        "test",
        runner_rtk(false, RtkPipedClaim::None),
    ),
    runner_rule(
        "runner-pnpm-test",
        &["pnpm"],
        &["test"],
        "test",
        runner_rtk(false, RtkPipedClaim::None),
    ),
    runner_rule(
        "runner-yarn-test",
        &["yarn"],
        &["test"],
        "test",
        runner_rtk(false, RtkPipedClaim::None),
    ),
    runner_rule(
        "runner-bun-test",
        &["bun"],
        &["test"],
        "test",
        runner_rtk(false, RtkPipedClaim::None),
    ),
    runner_rule(
        "runner-mvn-test",
        &["mvn"],
        &["test"],
        "test",
        runner_rtk(false, RtkPipedClaim::CommandSubcommand),
    ),
    runner_rule(
        "runner-gradle-test",
        &["gradle"],
        &["test"],
        "test",
        runner_rtk(false, RtkPipedClaim::None),
    ),
    runner_rule(
        "runner-gradlew-test",
        &["gradlew"],
        &["test"],
        "test",
        runner_rtk(false, RtkPipedClaim::None),
    ),
    runner_rule(
        "runner-cargo-build",
        &["cargo"],
        &["build"],
        "build",
        runner_rtk(true, RtkPipedClaim::CommandSubcommand),
    ),
    runner_rule(
        "runner-cargo-check",
        &["cargo"],
        &["check"],
        "build",
        runner_rtk(true, RtkPipedClaim::CommandSubcommand),
    ),
    runner_rule(
        "runner-cargo-clippy",
        &["cargo"],
        &["clippy"],
        "build",
        runner_rtk(true, RtkPipedClaim::CommandSubcommand),
    ),
    runner_rule(
        "runner-cargo-test",
        &["cargo"],
        &["test"],
        "test",
        runner_rtk(true, RtkPipedClaim::CommandSubcommand),
    ),
    runner_rule(
        "runner-go-build",
        &["go"],
        &["build"],
        "build",
        runner_rtk(true, RtkPipedClaim::CommandSubcommand),
    ),
    runner_rule(
        "runner-go-test",
        &["go"],
        &["test"],
        "test",
        runner_rtk(true, RtkPipedClaim::CommandSubcommand),
    ),
    runner_rule(
        "runner-tsc",
        &["tsc"],
        &[],
        "build",
        runner_rtk(true, RtkPipedClaim::None),
    ),
    runner_rule(
        "runner-pytest",
        &["pytest"],
        &[],
        "test",
        runner_rtk(true, RtkPipedClaim::LiteralPrefixes(&["pytest"])),
    ),
    runner_rule(
        "runner-jest",
        &["jest"],
        &[],
        "test",
        runner_rtk(true, RtkPipedClaim::None),
    ),
    runner_rule(
        "runner-vitest",
        &["vitest"],
        &[],
        "test",
        runner_rtk(true, RtkPipedClaim::None),
    ),
];

/// Enumerate every active shell rewrite rule and its declarative metadata.
pub fn shell_rewrite_rules() -> &'static [RewriteRule] {
    REWRITE_RULES
}

#[derive(Debug)]
struct FlagOccurrence {
    id: &'static str,
    value: Option<String>,
}

#[derive(Debug)]
struct Positional<'a> {
    token: &'a ShellToken,
    after_separator: bool,
}

#[derive(Debug, Default)]
struct ParsedArgs<'a> {
    flags: Vec<FlagOccurrence>,
    positionals: Vec<Positional<'a>>,
    saw_double_dash: bool,
}

struct HeadMatch<'a> {
    args_start: usize,
    git_c_dir: Option<&'a ShellToken>,
}

pub(super) struct RewriteContext<'a> {
    pub(super) kit_bin: &'a str,
    pub(super) truncated: bool,
    pub(super) pipe: Option<super::TerminalPipe>,
    pub(super) rest: &'a str,
    pub(super) cd_prefix: Option<&'a str>,
    pub(super) event_cwd: Option<&'a Path>,
}

/// Evaluate the rule table for one already tokenized shell command. The
/// returned string is only the command tail; the caller reapplies a leading
/// `cd ... &&` prefix.
pub(super) fn rewrite_with_rule_table(
    cmd0: &str,
    tokens: &[ShellToken],
    rtk_active: bool,
    context: &RewriteContext<'_>,
) -> Option<(String, crate::metrics::Rule)> {
    for rule in REWRITE_RULES {
        let Some(head) = match_head(rule, cmd0, tokens) else {
            continue;
        };
        if let Some(pipe) = context.pipe {
            let pipe_supported = match rule.target {
                TargetSpec::CompactRunner { .. } => pipe.is_runner_truncation(),
                TargetSpec::GitShowBlob => true,
                _ => false,
            };
            if !pipe_supported {
                continue;
            }
        }
        if rtk_defers(rule, rtk_active, context.truncated, context.rest, cmd0) {
            return None;
        }
        if context.truncated
            && matches!(
                rule.expansion,
                ExpansionRule::PreserveVerbatimOnce {
                    reject_when_truncated: true
                }
            )
            && (tokens.iter().any(|t| t.has_expansion)
                || context.cd_prefix.is_some_and(|prefix| {
                    shell_split(prefix).is_none_or(|ts| ts.iter().any(|t| t.has_expansion))
                }))
        {
            return None;
        }
        let parsed = parse_args(rule, &tokens[head.args_start..])?;
        return build_target(rule, &parsed, head.git_c_dir, context)
            .map(|rewritten| (rewritten, metric_rule(rule.target)));
    }
    None
}

fn match_head<'a>(
    rule: &RewriteRule,
    cmd0: &str,
    tokens: &'a [ShellToken],
) -> Option<HeadMatch<'a>> {
    if !rule.head.commands.contains(&cmd0) {
        return None;
    }
    let mut idx = 1usize;
    let mut git_c_dir = None;
    if rule.head.git_c_prefix {
        while let Some(tok) = tokens.get(idx) {
            if tok.value == "--no-pager" {
                idx += 1;
                continue;
            }
            if tok.value == "-C" && git_c_dir.is_none() {
                let dir = tokens.get(idx + 1)?;
                if dir.value.is_empty() || dir.has_expansion {
                    return None;
                }
                git_c_dir = Some(dir);
                idx += 2;
                continue;
            }
            break;
        }
    }
    for expected in rule.head.argv_prefix {
        if tokens.get(idx)?.value != *expected {
            return None;
        }
        idx += 1;
    }
    if let Some(required) = rule.head.first_positional_colon {
        let has_colon = tokens
            .get(idx)
            .is_some_and(|token| token.value.contains(':'));
        if has_colon != required {
            return None;
        }
    }
    Some(HeadMatch {
        args_start: idx,
        git_c_dir,
    })
}

fn rtk_defers(
    rule: &RewriteRule,
    rtk_active: bool,
    truncated: bool,
    rest: &str,
    cmd0: &str,
) -> bool {
    if !rtk_active {
        return false;
    }
    match rule.rtk.posture {
        RtkPosture::NeverDefer => false,
        RtkPosture::DeferWhenActive => true,
        RtkPosture::Runner {
            standalone_claimed,
            piped_claim,
        } => {
            if !truncated {
                return standalone_claimed;
            }
            match piped_claim {
                RtkPipedClaim::None => false,
                RtkPipedClaim::LiteralPrefixes(prefixes) => {
                    prefixes.iter().any(|prefix| word_prefix(rest, prefix))
                }
                RtkPipedClaim::CommandSubcommand => {
                    let Some(subcommand) = rule.head.argv_prefix.first() else {
                        return false;
                    };
                    rest.strip_prefix(cmd0)
                        .and_then(|s| s.strip_prefix(' '))
                        .is_some_and(|s| {
                            s.trim_start_matches([' ', '\t'])
                                .strip_prefix(subcommand)
                                .is_some_and(|tail| {
                                    tail.is_empty() || tail.starts_with([' ', '\t'])
                                })
                        })
                }
            }
        }
    }
}

/// Literal-prefix predicate for measured piped `rtk` replies: the claimed form
/// must end at end-of-string or a literal ASCII space.
fn word_prefix(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix)
        .is_some_and(|tail| tail.is_empty() || tail.starts_with(' '))
}

fn parse_args<'a>(rule: &RewriteRule, args: &'a [ShellToken]) -> Option<ParsedArgs<'a>> {
    let ParserSpec::Structured(spec) = rule.parser else {
        return Some(ParsedArgs::default());
    };
    let mut args = args;
    if spec.double_dash == DoubleDashSpec::OptionalPrefix
        && args.first().is_some_and(|tok| tok.value == "--")
    {
        args = &args[1..];
    }

    let mut parsed = ParsedArgs::default();
    let mut positional_only = false;
    let mut i = 0usize;
    while i < args.len() {
        let tok = &args[i];
        let arg = tok.value.as_str();
        if positional_only {
            parsed.positionals.push(Positional {
                token: tok,
                after_separator: true,
            });
            i += 1;
            continue;
        }
        if spec.double_dash == DoubleDashSpec::Boundary && arg == "--" {
            positional_only = true;
            parsed.saw_double_dash = true;
            i += 1;
            continue;
        }
        if !spec.flags_after_positionals && !parsed.positionals.is_empty() {
            return None;
        }
        if arg.starts_with('-') {
            let occurrences = parse_flag_token(&spec, args, &mut i)?;
            for occurrence in occurrences {
                let flag = spec.flags.iter().find(|flag| flag.id == occurrence.id)?;
                if flag.repeat == RepeatSpec::Once
                    && parsed.flags.iter().any(|seen| seen.id == occurrence.id)
                {
                    return None;
                }
                parsed.flags.push(occurrence);
            }
        } else {
            parsed.positionals.push(Positional {
                token: tok,
                after_separator: false,
            });
        }
        i += 1;
    }

    for flag in spec.flags.iter().filter(|flag| flag.required) {
        if !parsed.flags.iter().any(|seen| seen.id == flag.id) {
            return None;
        }
    }
    validate_positionals(&spec.positionals, &parsed.positionals)?;
    Some(parsed)
}

fn parse_flag_token(
    spec: &StructuredParserSpec,
    args: &[ShellToken],
    i: &mut usize,
) -> Option<Vec<FlagOccurrence>> {
    let tok = &args[*i];
    let arg = tok.value.as_str();

    for flag in spec.flags {
        if flag.exact.contains(&arg) {
            return Some(vec![flag_occurrence(flag, args, i, None)?]);
        }
    }

    for flag in spec.flags {
        for prefix in flag.attached_prefixes {
            if arg.starts_with(prefix) && arg.len() > prefix.len() {
                return Some(vec![flag_occurrence(
                    flag,
                    args,
                    i,
                    Some((&arg[prefix.len()..], tok.has_expansion)),
                )?]);
            }
        }
    }

    if let Some(id) = spec.numeric_short_flag {
        if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1 {
            let digits = &arg[1..];
            if digits.bytes().all(|b| b.is_ascii_digit()) {
                let flag = spec.flags.iter().find(|flag| flag.id == id)?;
                return Some(vec![validate_value_occurrence(flag, digits, false)?]);
            }
        }
    }

    if spec.short_clusters && arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1 {
        let mut occurrences = Vec::new();
        for ch in arg[1..].chars() {
            let flag = spec.flags.iter().find(|flag| flag.cluster == Some(ch))?;
            if flag.value.is_some() {
                return None;
            }
            occurrences.push(FlagOccurrence {
                id: flag.id,
                value: None,
            });
        }
        return Some(occurrences);
    }

    None
}

fn flag_occurrence(
    flag: &FlagSpec,
    args: &[ShellToken],
    i: &mut usize,
    attached: Option<(&str, bool)>,
) -> Option<FlagOccurrence> {
    let Some(value_spec) = flag.value else {
        return Some(FlagOccurrence {
            id: flag.id,
            value: None,
        });
    };
    let (value, has_expansion) = if let Some((value, has_expansion)) = attached {
        (value.to_owned(), has_expansion)
    } else {
        let value_token = args.get(*i + 1)?;
        *i += 1;
        (value_token.value.clone(), value_token.has_expansion)
    };
    validate_value(value_spec, &value, has_expansion, attached.is_some())?;
    Some(FlagOccurrence {
        id: flag.id,
        value: Some(value),
    })
}

fn validate_value_occurrence(
    flag: &FlagSpec,
    value: &str,
    has_expansion: bool,
) -> Option<FlagOccurrence> {
    validate_value(flag.value?, value, has_expansion, false)?;
    Some(FlagOccurrence {
        id: flag.id,
        value: Some(value.to_owned()),
    })
}

fn validate_value(spec: ValueSpec, value: &str, has_expansion: bool, attached: bool) -> Option<()> {
    if (spec.reject_empty && value.is_empty())
        || (spec.reject_expansion && has_expansion)
        || (attached && spec.reject_trailing_equals && value.ends_with('='))
    {
        return None;
    }
    match spec.validation {
        ValueValidation::Any => Some(()),
        ValueValidation::Usize => value.parse::<usize>().ok().map(|_| ()),
        ValueValidation::LangType => Lang::from_name(value).map(|_| ()),
        ValueValidation::DumpCount { allow_plus } => {
            let digits = if let Some(rest) = value.strip_prefix('+') {
                if !allow_plus {
                    return None;
                }
                rest
            } else {
                value
            };
            parse_dump_count(digits).map(|_| ())
        }
    }
}

fn validate_positionals(spec: &PositionalSpec, positionals: &[Positional<'_>]) -> Option<()> {
    if positionals.len() < spec.min || spec.max.is_some_and(|max| positionals.len() > max) {
        return None;
    }
    let before_count = positionals
        .iter()
        .filter(|pos| !pos.after_separator)
        .count();
    if spec
        .max_before_separator
        .is_some_and(|max| before_count > max)
    {
        return None;
    }
    for pos in positionals {
        let rule = if pos.after_separator {
            spec.after_separator
        } else {
            spec.before_separator
        };
        if (rule.reject_expansion && pos.token.has_expansion)
            || (rule.reject_empty && pos.token.value.is_empty())
            || (rule.reject_colon && pos.token.value.contains(':'))
            || (rule.require_colon && !pos.token.value.contains(':'))
        {
            return None;
        }
    }
    Some(())
}

fn flag_present(parsed: &ParsedArgs<'_>, id: &str) -> bool {
    parsed.flags.iter().any(|flag| flag.id == id)
}

fn flag_values<'a>(parsed: &'a ParsedArgs<'_>, id: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    parsed
        .flags
        .iter()
        .filter(move |flag| flag.id == id)
        .filter_map(|flag| flag.value.as_deref())
}

fn metric_rule(target: TargetSpec) -> crate::metrics::Rule {
    match target {
        TargetSpec::SliceSedRange | TargetSpec::GitShowBlob | TargetSpec::FileDump(_) => {
            crate::metrics::Rule::Slice
        }
        TargetSpec::GitStatus | TargetSpec::GitDiff | TargetSpec::GitShow => {
            crate::metrics::Rule::Diff
        }
        TargetSpec::SearchRg | TargetSpec::SearchGrep => crate::metrics::Rule::Search,
        TargetSpec::CompactLog | TargetSpec::CompactRunner { .. } => crate::metrics::Rule::Compact,
    }
}

fn build_target(
    rule: &RewriteRule,
    parsed: &ParsedArgs<'_>,
    git_c_dir: Option<&ShellToken>,
    context: &RewriteContext<'_>,
) -> Option<String> {
    let kit_bin = context.kit_bin;
    let rest = context.rest;
    match rule.target {
        TargetSpec::SliceSedRange => build_sed_range(parsed, kit_bin),
        TargetSpec::GitStatus => {
            let mut parts = git_diff_parts(kit_bin, git_c_dir)?;
            parts.push("--status".to_owned());
            Some(parts.join(" "))
        }
        TargetSpec::GitDiff => build_git_diff(
            parsed,
            git_c_dir,
            kit_bin,
            context.cd_prefix,
            context.event_cwd,
        ),
        TargetSpec::GitShow => build_git_show(parsed, git_c_dir, kit_bin),
        TargetSpec::GitShowBlob => build_git_show_blob(parsed, git_c_dir, kit_bin, context.pipe),
        TargetSpec::SearchRg => build_rg_search(parsed, kit_bin),
        TargetSpec::SearchGrep => build_grep_search(parsed, kit_bin),
        TargetSpec::FileDump(kind) => build_file_dump(kind, parsed, kit_bin),
        TargetSpec::CompactLog => Some(format!("{kit_bin} compact --mode log -- {rest}")),
        TargetSpec::CompactRunner { mode } => {
            let keep_log = if context.truncated { " --keep-log" } else { "" };
            Some(format!(
                "{kit_bin} compact --mode {mode}{keep_log} -- {rest}"
            ))
        }
    }
}

pub(super) fn parse_sed_range(expr: &str) -> Option<(usize, usize)> {
    let body = expr.strip_suffix('p')?;
    let (start_s, end_s) = body.split_once(',')?;
    if start_s.is_empty()
        || end_s.is_empty()
        || !start_s.bytes().all(|b| b.is_ascii_digit())
        || !end_s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let start: usize = start_s.parse().ok()?;
    let end: usize = end_s.parse().ok()?;
    if start >= 1 && end >= start {
        Some((start, end))
    } else {
        None
    }
}

fn is_safe_file_path(token: &ShellToken) -> bool {
    let p = token.value.as_str();
    !token.has_expansion
        && !p.is_empty()
        && p != "-"
        && !p.starts_with('-')
        && !p
            .chars()
            .any(|c| matches!(c, '$' | '*' | '?' | '[' | ']' | '~' | '{' | '}'))
}

fn parse_dump_count(value: &str) -> Option<usize> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: usize = value.parse().ok()?;
    if n >= 1 {
        Some(n)
    } else {
        None
    }
}

fn slice_command(kit_bin: &str, spec: String) -> Option<String> {
    Some(format!("{kit_bin} slice {}", try_shell_quote(&spec)?))
}

fn build_sed_range(parsed: &ParsedArgs<'_>, kit_bin: &str) -> Option<String> {
    let range = parsed.positionals.first()?.token.value.as_str();
    let file = parsed.positionals.get(1)?.token;
    let (start, end) = parse_sed_range(range)?;
    if !is_safe_file_path(file) {
        return None;
    }
    slice_command(kit_bin, format!("{}:{start}-{end}", file.value))
}

fn git_diff_parts(kit_bin: &str, git_c_dir: Option<&ShellToken>) -> Option<Vec<String>> {
    let mut parts = vec![kit_bin.to_owned(), "diff".to_owned()];
    if let Some(dir) = git_c_dir {
        parts.push("--root".to_owned());
        parts.push(try_shell_quote(&dir.value)?);
    }
    Some(parts)
}

fn resolve_git_dir(
    cd_prefix: Option<&str>,
    git_c_dir: Option<&str>,
    event_cwd: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(dir) = git_c_dir {
        let p = PathBuf::from(dir);
        if p.is_absolute() {
            return Some(p);
        }
        return event_cwd.map(|c| c.join(p));
    }
    if let Some(prefix) = cd_prefix {
        if let Some(tokens) = shell_split(prefix) {
            if tokens.len() == 2 && !tokens[1].has_expansion {
                let p = PathBuf::from(&tokens[1].value);
                if p.is_absolute() {
                    return Some(p);
                }
                return event_cwd.map(|c| c.join(p));
            }
        }
    }
    event_cwd.map(Path::to_path_buf)
}

fn build_git_diff(
    parsed: &ParsedArgs<'_>,
    git_c_dir: Option<&ShellToken>,
    kit_bin: &str,
    cd_prefix: Option<&str>,
    event_cwd: Option<&Path>,
) -> Option<String> {
    let mut parts = git_diff_parts(kit_bin, git_c_dir)?;
    let staged = flag_present(parsed, "staged");
    let stat = flag_present(parsed, "stat");
    let context = flag_values(parsed, "unified")
        .last()
        .and_then(|value| value.parse::<usize>().ok());
    let mut base_ref = parsed
        .positionals
        .iter()
        .find(|pos| !pos.after_separator)
        .map(|pos| pos.token);
    let mut paths: Vec<&ShellToken> = parsed
        .positionals
        .iter()
        .filter(|pos| pos.after_separator)
        .map(|pos| pos.token)
        .collect();

    if let Some(candidate) = base_ref {
        let repo_dir = resolve_git_dir(
            cd_prefix,
            git_c_dir.map(|token| token.value.as_str()),
            event_cwd,
        );
        let exists_as_path = paths.is_empty()
            && !parsed.saw_double_dash
            && repo_dir.is_some_and(|dir| dir.join(&candidate.value).exists());
        if exists_as_path {
            paths.push(candidate);
            base_ref = None;
        } else if staged {
            // `prometheus-kit diff` treats --staged and --base as mutually exclusive.
            return None;
        }
    }

    if staged {
        parts.push("--staged".to_owned());
    }
    if stat {
        parts.push("--stat".to_owned());
    }
    if let Some(n) = context {
        parts.push("-C".to_owned());
        parts.push(n.to_string());
    }
    if let Some(base) = base_ref {
        parts.push("--base".to_owned());
        parts.push(try_shell_quote(&base.value)?);
    }
    if !paths.is_empty() {
        parts.push("--".to_owned());
        for path in paths {
            parts.push(try_shell_quote(&path.value)?);
        }
    }
    Some(parts.join(" "))
}

fn split_git_rev_path(value: &str) -> Option<(&str, &str)> {
    let mut parts = value.split(':');
    let rev = parts.next()?;
    let path = parts.next()?;
    if parts.next().is_some()
        || rev.len() <= 1
        || rev.starts_with('-')
        || rev.chars().any(|c| c.is_whitespace() || c.is_control())
        || path.is_empty()
        || path.starts_with(['-', '/'])
        || path
            .chars()
            .any(|c| {
                c.is_control() || matches!(c, '$' | '*' | '?' | '[' | ']' | '~' | '{' | '}')
            })
    {
        return None;
    }
    Some((rev, path))
}

fn build_git_show_blob(
    parsed: &ParsedArgs<'_>,
    git_c_dir: Option<&ShellToken>,
    kit_bin: &str,
    pipe: Option<super::TerminalPipe>,
) -> Option<String> {
    let operand = parsed.positionals.first()?.token.value.as_str();
    let (rev, path) = split_git_rev_path(operand)?;
    let spec = match pipe {
        Some(super::TerminalPipe::Head(0)) | Some(super::TerminalPipe::Tail(0)) => return None,
        Some(super::TerminalPipe::Head(n)) => format!("{path}:1-{n}"),
        Some(super::TerminalPipe::Tail(n)) => format!("{path}:-{n}"),
        Some(super::TerminalPipe::Range(start, end)) => format!("{path}:{start}-{end}"),
        Some(super::TerminalPipe::NumberedWhole) | None => format!("{path}:1-"),
    };
    let mut parts = vec![
        kit_bin.to_owned(),
        "slice".to_owned(),
        "--rev".to_owned(),
        try_shell_quote(rev)?,
    ];
    if let Some(dir) = git_c_dir {
        parts.push("--root".to_owned());
        parts.push(try_shell_quote(&dir.value)?);
    }
    parts.push(try_shell_quote(&spec)?);
    Some(parts.join(" "))
}

fn build_git_show(
    parsed: &ParsedArgs<'_>,
    git_c_dir: Option<&ShellToken>,
    kit_bin: &str,
) -> Option<String> {
    let mut parts = git_diff_parts(kit_bin, git_c_dir)?;
    let rev = parsed.positionals.first()?.token;
    parts.push("--commit".to_owned());
    parts.push(try_shell_quote(&rev.value)?);
    if flag_present(parsed, "stat") {
        parts.push("--stat".to_owned());
    }
    Some(parts.join(" "))
}

fn search_parts(parsed: &ParsedArgs<'_>, kit_bin: &str) -> Vec<String> {
    let mut parts = vec![kit_bin.to_owned(), "search".to_owned()];
    if flag_present(parsed, "ignore-case") {
        parts.push("-i".to_owned());
    }
    if flag_present(parsed, "fixed-strings") {
        parts.push("-F".to_owned());
    }
    if flag_present(parsed, "word-regexp") {
        parts.push("-w".to_owned());
    }
    if flag_present(parsed, "files-only") {
        parts.push("--files-only".to_owned());
    }
    parts
}

fn push_globs_and_type(
    parts: &mut Vec<String>,
    parsed: &ParsedArgs<'_>,
    include_type: bool,
) -> Option<()> {
    for glob in flag_values(parsed, "glob").chain(flag_values(parsed, "include")) {
        parts.push("--glob".to_owned());
        parts.push(try_shell_quote(glob)?);
    }
    if include_type {
        if let Some(lang_type) = flag_values(parsed, "type").last() {
            parts.push("--type".to_owned());
            parts.push(try_shell_quote(lang_type)?);
        }
    }
    Some(())
}

fn build_rg_search(parsed: &ParsedArgs<'_>, kit_bin: &str) -> Option<String> {
    let mut parts = search_parts(parsed, kit_bin);
    if flag_present(parsed, "hidden") {
        parts.push("--hidden".to_owned());
    }
    if flag_present(parsed, "no-ignore") {
        parts.push("--no-ignore".to_owned());
    }
    push_globs_and_type(&mut parts, parsed, true)?;
    parts.push("--symbols".to_owned());
    parts.push("--".to_owned());
    for pos in &parsed.positionals {
        parts.push(try_shell_quote(&pos.token.value)?);
    }
    Some(parts.join(" "))
}

fn build_grep_search(parsed: &ParsedArgs<'_>, kit_bin: &str) -> Option<String> {
    let mut positionals: Vec<&str> = parsed
        .positionals
        .iter()
        .map(|pos| pos.token.value.as_str())
        .collect();
    let pattern = if let Some(pattern) = flag_values(parsed, "pattern").last() {
        pattern
    } else {
        if positionals.is_empty() {
            return None;
        }
        positionals.remove(0)
    };
    // `grep` needs at least one explicit path here: with none it reads stdin
    // or the working tree implicitly, which `search` does not reproduce.
    if positionals.is_empty() {
        return None;
    }

    let mut parts = search_parts(parsed, kit_bin);
    push_globs_and_type(&mut parts, parsed, false)?;
    parts.push("--symbols".to_owned());
    parts.push("--".to_owned());
    parts.push(try_shell_quote(pattern)?);
    for pos in positionals {
        parts.push(try_shell_quote(pos)?);
    }
    Some(parts.join(" "))
}

fn build_file_dump(kind: FileDumpKind, parsed: &ParsedArgs<'_>, kit_bin: &str) -> Option<String> {
    let file = parsed.positionals.first()?.token;
    if !is_safe_file_path(file) {
        return None;
    }
    if kind == FileDumpKind::Whole {
        return slice_command(kit_bin, format!("{}:1-", file.value));
    }

    let mut count: Option<usize> = None;
    let mut from_line: Option<usize> = None;
    for value in flag_values(parsed, "count") {
        if let Some(rest) = value.strip_prefix('+') {
            from_line = Some(parse_dump_count(rest)?);
        } else {
            count = Some(parse_dump_count(value)?);
        }
    }

    if kind == FileDumpKind::Head {
        if from_line.is_some() {
            return None;
        }
        let n = count.unwrap_or(10);
        slice_command(kit_bin, format!("{}:1-{n}", file.value))
    } else if let Some(n) = from_line {
        slice_command(kit_bin, format!("{}:{n}-", file.value))
    } else {
        let n = count.unwrap_or(10);
        slice_command(kit_bin, format!("{}:-{n}", file.value))
    }
}
