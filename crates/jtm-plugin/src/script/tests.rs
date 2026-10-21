use std::cmp::Ordering;
use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use super::*;

const MANIFEST: &str = r#"
schema = 1
name = "demo"
display_name = "Demo"

[versions]
scheme = "maven"
"#;

fn host() -> Host {
    Host {
        platform: "linux-x64".to_owned(),
        os: "linux".to_owned(),
        arch: "x64".to_owned(),
    }
}

fn script(source: &str) -> Script {
    Script::new("demo", source, MANIFEST, Some(VersionScheme::Maven), host())
        .unwrap_or_else(|e| panic!("script should load: {e}"))
}

/// A script with short limits, so limit tests run quickly.
fn tight(source: &str) -> Script {
    script(source).with_limits(Limits {
        memory: 8 * 1024 * 1024,
        time: Duration::from_millis(200),
    })
}

/// Runs `body` as `function f() ... end` through `format_interop`, which returns a string.
fn eval(source: &str) -> Result<String, ScriptError> {
    script(&format!("function f(file, variant, value)\n{source}\nend"))
        .format_interop("f", "file", "default", "1")
}

fn ok(source: &str) -> String {
    eval(source).unwrap_or_else(|e| panic!("`{source}` should run: {e}"))
}

#[derive(Debug)]
struct Entry {
    variant: &'static str,
    version: &'static str,
    tags: Vec<String>,
}

impl Candidate for Entry {
    fn variant(&self) -> &str {
        self.variant
    }
    fn version(&self) -> &str {
        self.version
    }
    fn tags(&self) -> &[String] {
        &self.tags
    }
}

fn entries() -> Vec<Entry> {
    vec![
        Entry {
            variant: "default",
            version: "3.9.9",
            tags: vec!["stable".to_owned()],
        },
        Entry {
            variant: "default",
            version: "4.0.0-rc-2",
            tags: vec![],
        },
    ]
}

fn limit_of(result: Result<impl std::fmt::Debug, ScriptError>) -> Limit {
    match result {
        Err(ScriptError::Limit { limit, .. }) => limit,
        other => panic!("expected a limit breach, got {other:?}"),
    }
}

fn is_path_limit(result: Result<impl std::fmt::Debug, ScriptError>) -> bool {
    matches!(limit_of(result), Limit::Path { .. })
}

// --- hooks ---

#[test]
fn resolve_alias_returns_the_version_the_script_picks() {
    let s = script(
        r#"
        function pick(alias, variant, candidates)
            for _, c in ipairs(candidates) do
                for _, tag in ipairs(c.tags) do
                    if tag == alias and c.variant == variant then return c.version end
                end
            end
            return nil
        end
        "#,
    );
    assert_eq!(
        s.resolve_alias("pick", "stable", "default", &entries()),
        Ok(Some("3.9.9".to_owned()))
    );
    assert_eq!(
        s.resolve_alias("pick", "lts", "default", &entries()),
        Ok(None)
    );
}

#[test]
fn resolve_alias_refuses_a_value_that_is_not_a_version() {
    let s = script("function pick() return '../../etc' end");
    assert!(matches!(
        s.resolve_alias("pick", "x", "default", &entries()),
        Err(ScriptError::Invalid { .. })
    ));
    let s = script("function pick() return 3 end");
    assert!(matches!(
        s.resolve_alias("pick", "x", "default", &entries()),
        Err(ScriptError::Invalid { .. })
    ));
}

#[test]
fn resolve_alias_must_pick_one_of_the_candidates() {
    // An alias name, a version the index does not list, and one listed only for another
    // variant are all refused.
    for (picked, variant) in [
        ("lts", "default"),
        ("latest", "default"),
        ("9.9.9", "default"),
        ("3.9.9", "other"),
    ] {
        let s = script(&format!("function pick() return '{picked}' end"));
        let result = s.resolve_alias("pick", "x", variant, &entries());
        match result {
            Err(ScriptError::Invalid { message, .. }) => {
                assert!(message.contains(picked), "{message}");
                assert!(message.contains("is not the version of any"), "{message}");
            }
            other => panic!("`{picked}` should be refused, got {other:?}"),
        }
    }
    let s = script("function pick() return '4.0.0-rc-2' end");
    assert_eq!(
        s.resolve_alias("pick", "x", "default", &entries()),
        Ok(Some("4.0.0-rc-2".to_owned()))
    );
}

#[test]
fn compare_versions_maps_the_sign_to_an_ordering() {
    let s = script("function cmp(a, b) return jtm.version.compare(a, b) end");
    assert_eq!(
        s.compare_versions("cmp", "3.9.9", "3.10.0"),
        Ok(Ordering::Less)
    );
    assert_eq!(
        s.compare_versions("cmp", "3.10.0", "3.9.9"),
        Ok(Ordering::Greater)
    );
    assert_eq!(
        s.compare_versions("cmp", "3.9", "3.9.0"),
        Ok(Ordering::Equal)
    );
    let s = script("function cmp() return 0/0 end");
    assert!(matches!(
        s.compare_versions("cmp", "1", "2"),
        Err(ScriptError::Invalid { .. })
    ));
}

#[test]
fn parse_interop_accepts_a_string_or_a_table() {
    let s = script(
        r#"
        function parse(file, text)
            local v = jtm.regex.match("^demo=([0-9.]+)-(\\w+)$", jtm.string.trim(text))
            if v == nil then return nil end
            if v[3] == "x" then return v[2] end
            return { variant = v[3], value = v[2] }
        end
        "#,
    );
    assert_eq!(
        s.parse_interop("parse", ".demorc", "demo=1.2-tem\n"),
        Ok(Some(InteropValue {
            variant: Some("tem".to_owned()),
            value: "1.2".to_owned(),
        }))
    );
    assert_eq!(
        s.parse_interop("parse", ".demorc", "demo=1.2-x"),
        Ok(Some(InteropValue {
            variant: None,
            value: "1.2".to_owned(),
        }))
    );
    assert_eq!(s.parse_interop("parse", ".demorc", "other"), Ok(None));
}

#[test]
fn parse_interop_refuses_a_bad_variant() {
    let s = script("function parse() return { variant = 'Bad Variant', value = '1' } end");
    assert!(matches!(
        s.parse_interop("parse", "f", ""),
        Err(ScriptError::Invalid { .. })
    ));
}

#[test]
fn format_interop_returns_one_line() {
    let s = script("function fmt(file, variant, value) return value .. '-' .. variant end");
    assert_eq!(
        s.format_interop("fmt", "f", "tem", "21"),
        Ok("21-tem".to_owned())
    );
    let s = script("function fmt() return 'a\\nb' end");
    assert!(matches!(
        s.format_interop("fmt", "f", "tem", "21"),
        Err(ScriptError::Invalid { .. })
    ));
}

#[test]
fn a_missing_function_or_syntax_error_is_invalid() {
    assert!(matches!(eval_missing(), Err(ScriptError::Invalid { .. })));
    assert!(matches!(
        Script::new("demo", "function (", MANIFEST, None, host()),
        Err(ScriptError::Invalid { .. })
    ));
}

fn eval_missing() -> Result<String, ScriptError> {
    script("x = 1").format_interop("nope", "f", "v", "1")
}

#[test]
fn a_runtime_error_is_a_failure_with_its_message() {
    match eval("error('boom')") {
        Err(ScriptError::Failed { hook, message }) => {
            assert_eq!(hook, "format_interop");
            assert!(message.contains("boom"), "{message}");
        }
        other => panic!("expected a failure, got {other:?}"),
    }
}

// --- host API ---

#[test]
fn the_host_api_exposes_platform_manifest_and_helpers() {
    assert_eq!(
        ok("return jtm.platform.name .. ' ' .. jtm.platform.os .. ' ' .. jtm.platform.arch"),
        "linux-x64 linux x64"
    );
    assert_eq!(
        ok("return jtm.plugin .. ' ' .. jtm.manifest.versions.scheme"),
        "demo maven"
    );
    assert_eq!(
        ok("return tostring(jtm.version.matches_prefix('21.0.5+11', '21', 'java'))"),
        "true"
    );
    assert_eq!(
        ok("return tostring(jtm.version.is_prerelease('4.0.0-rc-2'))"),
        "true"
    );
    assert_eq!(
        ok(
            "local v, err = jtm.version.parse('', 'java') return tostring(v) .. ' ' .. tostring(err ~= nil)"
        ),
        "nil true"
    );
    assert_eq!(
        ok("return jtm.json.decode('{\"a\": [1, \"b\"]}').a[2]"),
        "b"
    );
    assert_eq!(
        ok("return table.concat(jtm.string.split('a,b,,c', ','), '|')"),
        "a|b||c"
    );
    assert_eq!(
        ok("return tostring(jtm.regex.is_match('^v\\\\d+$', 'v12'))"),
        "true"
    );
    assert_eq!(
        ok(
            "return tostring(jtm.string.starts_with('abc', 'ab') and jtm.string.ends_with('abc', 'bc'))"
        ),
        "true"
    );
    assert_eq!(ok("return tostring(jtm.fs)"), "nil");
}

#[test]
fn the_host_api_and_standard_libraries_are_read_only() {
    for source in [
        "jtm.plugin = 'other'",
        "jtm.manifest.name = 'other'",
        "jtm.manifest.versions.scheme = 'java'",
        "jtm.version.compare = nil",
        "string.upper = nil",
        "table.insert = nil",
        "getmetatable('').__index = {}",
    ] {
        assert!(
            matches!(eval(source), Err(ScriptError::Failed { .. })),
            "`{source}` should be refused"
        );
    }
}

#[test]
fn a_script_cannot_replace_globals_for_later_hooks() {
    // Each call gets a fresh state, so nothing a script sets survives into the next one.
    let s = script("function set() counter = (counter or 0) + 1 return tostring(counter) end");
    assert_eq!(s.format_interop("set", "f", "v", "1"), Ok("1".to_owned()));
    assert_eq!(s.format_interop("set", "f", "v", "1"), Ok("1".to_owned()));
}

// --- sandbox escapes ---

#[test]
fn unsafe_libraries_and_functions_are_absent() {
    for name in [
        "io",
        "os",
        "debug",
        "package",
        "require",
        "loadstring",
        "load",
        "dofile",
        "loadfile",
        "print",
        "getfenv",
        "setfenv",
        "collectgarbage",
        "gcinfo",
        "coroutine",
        "bit32",
        "buffer",
    ] {
        assert_eq!(
            ok(&format!("return type({name})")),
            "nil",
            "`{name}` should be absent"
        );
    }
    for name in ["string", "table", "math", "utf8"] {
        assert_eq!(
            ok(&format!("return type({name})")),
            "table",
            "`{name}` should load"
        );
    }
}

#[test]
fn bytecode_is_refused() {
    let bytecode = mlua::chunk::Compiler::new()
        .compile("function f() return 'x' end")
        .unwrap_or_default();
    let text = String::from_utf8_lossy(&bytecode).into_owned();
    assert!(matches!(
        Script::new("demo", &text, MANIFEST, None, host()),
        Err(ScriptError::Invalid { .. })
    ));
}

#[test]
fn deep_recursion_fails_without_crashing() {
    assert!(matches!(
        eval("local function f(n) return f(n + 1) + 1 end return tostring(f(1))"),
        Err(ScriptError::Failed { .. })
    ));
    // Each protected call goes through the host, so nesting them is bounded too.
    for source in [
        "local function f() return pcall(f) end return tostring((f()))",
        "local function f() return xpcall(f, f) end return tostring((f()))",
    ] {
        // The innermost call fails on the C stack limit, and every outer one succeeds.
        assert_eq!(ok(source), "true", "{source}");
    }
}

#[test]
fn a_cyclic_or_odd_return_value_is_invalid() {
    assert!(matches!(
        script("function f() local t = {} t.self = t return { variant = 'x', value = t } end")
            .parse_interop("f", "f", ""),
        Err(ScriptError::Invalid { .. })
    ));
    assert!(matches!(
        script("function f() return function() end end").parse_interop("f", "f", ""),
        Err(ScriptError::Invalid { .. })
    ));
}

#[test]
fn a_shared_subtable_cannot_expand_into_a_huge_result() {
    let s = script(
        r#"
        function f()
            local t = { "x" }
            for _ = 1, 40 do t = { t, t } end
            return { value = "1", extra = t }
        end
        "#,
    );
    assert!(matches!(
        s.parse_interop("f", "f", ""),
        Err(ScriptError::Invalid { .. })
    ));
}

// --- limits ---

#[test]
fn exceeding_the_memory_limit_is_a_limit_breach() {
    let s = tight(
        r#"
        function f()
            local t = {}
            for i = 1, 1e9 do t[i] = string.rep("x", 4096) .. i end
        end
        "#,
    );
    assert_eq!(
        limit_of(s.format_interop("f", "f", "v", "1")),
        Limit::Memory(8 * 1024 * 1024)
    );
}

#[test]
fn one_huge_allocation_is_a_limit_breach() {
    let s = tight("function f() return string.rep('x', 64 * 1024 * 1024) end");
    assert!(matches!(
        limit_of(s.format_interop("f", "f", "v", "1")),
        Limit::Memory(_)
    ));
}

#[test]
fn an_endless_loop_is_stopped_by_the_time_limit() {
    let s = tight("function f() while true do end end");
    let start = Instant::now();
    assert_eq!(
        limit_of(s.format_interop("f", "f", "v", "1")),
        Limit::Time(Duration::from_millis(200))
    );
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn catching_the_time_limit_does_not_help() {
    let s = tight(
        r#"
        function f()
            for _ = 1, 1e12 do pcall(function() while true do end end) end
            return "1"
        end
        "#,
    );
    assert!(matches!(
        limit_of(s.format_interop("f", "f", "v", "1")),
        Limit::Time(_)
    ));
    let s = tight("function f() pcall(function() while true do end end) return '1' end");
    assert!(matches!(
        limit_of(s.format_interop("f", "f", "v", "1")),
        Limit::Time(_)
    ));
}

#[test]
fn loading_the_script_counts_towards_the_time_limit() {
    let s = tight("while true do end function f() return '1' end");
    assert!(matches!(
        limit_of(s.format_interop("f", "f", "v", "1")),
        Limit::Time(_)
    ));
}

#[test]
fn a_slow_pattern_match_is_stopped_at_the_deadline() {
    // Lua patterns backtrack inside one C call; Luau still stops it at the deadline.
    let s = tight(
        r#"
        function f()
            -- Anchored, so even a missed interrupt would end within a few seconds.
            local s = string.rep("a", 3000)
            string.find(s, "^.-.-.-b")
            return "1"
        end
        "#,
    );
    let start = Instant::now();
    assert!(matches!(
        limit_of(s.format_interop("f", "f", "v", "1")),
        Limit::Time(_)
    ));
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn abandoning_a_hook_waits_for_its_file_operation() {
    let shared = Arc::new(Shared::new(Limits::default()));
    let (started, wait) = mpsc::channel();
    let (go, end) = mpsc::channel::<()>();
    let worker = Arc::clone(&shared);
    let thread = std::thread::spawn(move || {
        let busy = worker
            .enter()
            .unwrap_or_else(|| panic!("not abandoned yet"));
        started.send(()).unwrap_or_else(|e| panic!("{e}"));
        std::thread::sleep(Duration::from_millis(300));
        drop(busy);
        // The hook goes on running after its file operation, until the test lets it end.
        end.recv().unwrap_or_else(|e| panic!("{e}"));
        worker.finish()
    });
    wait.recv().unwrap_or_else(|e| panic!("{e}"));
    let start = Instant::now();
    shared.cut_off();
    assert!(shared.abandon(), "the thread was still running");
    assert!(
        start.elapsed() >= Duration::from_millis(200),
        "abandon returned early"
    );
    assert!(
        shared.enter().is_none(),
        "no file operation starts once abandoned"
    );
    go.send(()).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        thread.join().unwrap_or_else(|_| panic!("thread panicked")),
        "the thread learns it was abandoned"
    );
}

#[test]
fn a_panicking_abandoned_hook_still_releases_its_count() {
    static STUCK: AtomicUsize = AtomicUsize::new(1);
    let shared = Arc::new(Shared::new(Limits::default()));
    assert!(shared.abandon());
    let finish = Finish {
        shared: Arc::clone(&shared),
        stuck: &STUCK,
    };
    let panicked = std::thread::spawn(move || {
        let _finish = finish;
        panic!("a bug in a host function");
    })
    .join();
    assert!(panicked.is_err());
    assert_eq!(STUCK.load(AtomicOrdering::SeqCst), 0);
}

#[test]
fn no_file_operation_starts_after_the_deadline() {
    let shared = Shared::new(Limits {
        memory: MEMORY_LIMIT,
        time: Duration::ZERO,
    });
    assert!(
        shared.enter().is_none(),
        "the grace period allows no new work"
    );
}

#[test]
fn a_hook_that_finishes_first_is_not_abandoned() {
    let shared = Shared::new(Limits::default());
    assert!(!shared.finish());
    assert!(!shared.abandon());
}

#[test]
fn too_many_stuck_hooks_refuse_the_next_one() {
    static STUCK: AtomicUsize = AtomicUsize::new(0);
    // Enough time to reach the sleep on a loaded runner, and a sleep that outlasts all the calls.
    let limits = Limits {
        memory: 8 * 1024 * 1024,
        time: Duration::from_millis(500),
    };
    let s = script(
        r#"
        function f()
            jtm.sleep(8000)
            return "1"
        end
        "#,
    )
    .with_limits(limits)
    .with_stuck_counter(&STUCK);
    for stuck in 1..=MAX_STUCK {
        assert!(matches!(
            limit_of(s.format_interop("f", "f", "v", "1")),
            Limit::Time(_)
        ));
        assert_eq!(STUCK.load(AtomicOrdering::SeqCst), stuck);
    }
    assert!(
        matches!(
            limit_of(s.format_interop("f", "f", "v", "1")),
            Limit::Stuck(MAX_STUCK)
        ),
        "the stuck hooks were counted"
    );
    // Each abandoned thread is released when its sleep ends.
    let start = Instant::now();
    while STUCK.load(AtomicOrdering::SeqCst) > 0 {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "stuck hooks never ended"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let quick = tight(r#"function f() return "1" end"#).with_stuck_counter(&STUCK);
    assert_eq!(
        quick
            .format_interop("f", "f", "v", "1")
            .unwrap_or_else(|e| panic!("{e}")),
        "1"
    );
}

// --- post_extract ---

fn install_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let root = dir.path();
    fs::create_dir_all(root.join("bin")).unwrap_or_else(|e| panic!("{e}"));
    fs::create_dir_all(root.join("lib/nested")).unwrap_or_else(|e| panic!("{e}"));
    fs::write(root.join("bin/tool"), "#!/bin/sh\n").unwrap_or_else(|e| panic!("{e}"));
    fs::write(root.join("lib/nested/a.txt"), "a").unwrap_or_else(|e| panic!("{e}"));
    fs::write(root.join("README"), "readme").unwrap_or_else(|e| panic!("{e}"));
    dir
}

const CONTEXT: PostExtract<'static> = PostExtract {
    variant: "default",
    version: "1.0",
    home: "",
};

fn post_extract(root: &Path, body: &str) -> Result<(), ScriptError> {
    script(&format!("function post(ctx)\n{body}\nend")).post_extract("post", root, &CONTEXT)
}

#[test]
fn an_install_dir_jtm_cannot_open_is_an_io_error() {
    let dir = install_dir();
    let missing = dir.path().join("missing");
    match post_extract(&missing, "") {
        Err(ScriptError::Io { path, kind, .. }) => {
            assert_eq!(path, missing);
            assert_eq!(kind, std::io::ErrorKind::NotFound);
        }
        other => panic!("expected an IO error, got {other:?}"),
    }
}

#[test]
fn host_side_failures_say_jtm_could_not_run_the_hook() {
    let io = ScriptError::Io {
        hook: "post".to_owned(),
        path: PathBuf::from("install"),
        kind: std::io::ErrorKind::PermissionDenied,
        message: "access denied".to_owned(),
    };
    assert_eq!(
        io.to_string(),
        "cannot run hook `post`: cannot access install: access denied"
    );
    let host = ScriptError::Host {
        hook: "post".to_owned(),
        message: "the script engine stopped unexpectedly".to_owned(),
    };
    assert_eq!(
        host.to_string(),
        "cannot run hook `post`: the script engine stopped unexpectedly"
    );
}

#[test]
fn post_extract_can_rename_move_remove_and_list() {
    let dir = install_dir();
    let root = dir.path();
    post_extract(
        root,
        r#"
        assert(ctx.version == "1.0" and ctx.variant == "default")
        assert(jtm.fs.exists("bin/tool") and jtm.fs.is_dir("lib"))
        assert(table.concat(jtm.fs.list("."), ",") == "README,bin,lib")
        jtm.fs.rename("bin/tool", "bin/tool2")
        jtm.fs.move("lib/nested/a.txt", "a.txt")
        jtm.fs.remove("lib")
        jtm.fs.remove("README")
        jtm.fs.chmod("bin/tool2", tonumber("755", 8))
        "#,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(root.join("bin/tool2").is_file());
    assert!(root.join("a.txt").is_file());
    assert!(!root.join("lib").exists());
    assert!(!root.join("README").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(root.join("bin/tool2"))
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or_default();
        assert_eq!(mode, 0o755);
    }
}

#[test]
fn ordinary_file_errors_can_be_caught() {
    let dir = install_dir();
    post_extract(
        dir.path(),
        r#"
        assert(not pcall(jtm.fs.remove, "missing"))
        assert(not pcall(jtm.fs.rename, "README", "bin"))
        assert(not pcall(jtm.fs.chmod, "README", tonumber("4755", 8)))
        assert(not pcall(jtm.fs.remove, "."))
        "#,
    )
    .unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn paths_outside_the_install_dir_are_refused() {
    let outside = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let victim = outside.path().join("victim");
    fs::write(&victim, "keep").unwrap_or_else(|e| panic!("{e}"));
    let dir = install_dir();
    let abs = victim.display().to_string().replace('\\', "/");
    for call in [
        "jtm.fs.remove('../victim')".to_owned(),
        "jtm.fs.remove('bin/../../victim')".to_owned(),
        format!("jtm.fs.remove({abs:?})"),
        "jtm.fs.remove('C:/victim')".to_owned(),
        "jtm.fs.remove('bin\\\\..\\\\..\\\\victim')".to_owned(),
        "jtm.fs.rename('README', '../stolen')".to_owned(),
        "jtm.fs.rename('../victim', 'here')".to_owned(),
        "jtm.fs.chmod('..', 511)".to_owned(),
        "jtm.fs.list('..')".to_owned(),
        "jtm.fs.exists('../victim')".to_owned(),
        "jtm.fs.remove('a\\0b')".to_owned(),
    ] {
        assert!(
            is_path_limit(post_extract(dir.path(), &call)),
            "`{call}` should breach containment"
        );
    }
    assert!(victim.is_file());
}

#[test]
fn catching_a_containment_error_does_not_help() {
    let dir = install_dir();
    assert!(is_path_limit(post_extract(
        dir.path(),
        "pcall(jtm.fs.remove, '../victim')"
    )));
}

#[cfg(unix)]
#[test]
fn paths_through_a_link_are_refused() {
    let outside = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    fs::write(outside.path().join("victim"), "keep").unwrap_or_else(|e| panic!("{e}"));
    let dir = install_dir();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("out"))
        .unwrap_or_else(|e| panic!("{e}"));
    // Removing the link itself is fine once it is gone; going through it is not.
    assert!(is_path_limit(post_extract(
        dir.path(),
        "jtm.fs.remove('out/victim')"
    )));
    assert!(is_path_limit(post_extract(
        dir.path(),
        "jtm.fs.chmod('out/victim', 511)"
    )));
    assert!(outside.path().join("victim").is_file());
}

#[cfg(unix)]
#[test]
fn chmod_refuses_links() {
    let dir = install_dir();
    std::os::unix::fs::symlink("README", dir.path().join("link")).unwrap_or_else(|e| panic!("{e}"));
    post_extract(dir.path(), "assert(not pcall(jtm.fs.chmod, 'link', 511))")
        .unwrap_or_else(|e| panic!("{e}"));
}

#[cfg(unix)]
#[test]
fn moving_a_link_so_it_points_outside_fails_the_hook() {
    let dir = install_dir();
    // `lib/nested/up` points at `lib`, inside; moved to the top it would point above the root.
    std::os::unix::fs::symlink("../..", dir.path().join("lib/nested/up"))
        .unwrap_or_else(|e| panic!("{e}"));
    post_extract(dir.path(), "").unwrap_or_else(|e| panic!("{e}"));
    assert!(is_path_limit(post_extract(
        dir.path(),
        "jtm.fs.move('lib/nested/up', 'up')"
    )));
}

#[cfg(unix)]
#[test]
fn a_link_that_escapes_through_another_link_fails_the_hook() {
    let dir = install_dir();
    // Each target looks inside on its own, but `here/..` is the root's parent.
    std::os::unix::fs::symlink(".", dir.path().join("here")).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink("here/..", dir.path().join("escape"))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(is_path_limit(post_extract(dir.path(), "")));
}

/// Gives every directory under its path back `0o755` when dropped, so a test that fails while
/// a directory is locked still leaves a temp dir that can be removed. Declare it after the
/// temp dir, so it is dropped first.
#[cfg(unix)]
struct Unlock<'a>(&'a Path);

#[cfg(unix)]
impl Drop for Unlock<'_> {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        let open = |path: &Path| fs::set_permissions(path, fs::Permissions::from_mode(0o755));
        let _ = open(self.0);
        let _ = jtm_archive::tree::walk(self.0, |entry| {
            if entry.kind.is_dir() {
                let _ = open(&entry.path);
            }
            Ok::<(), jtm_archive::tree::ReadError>(())
        });
    }
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    fs::symlink_metadata(path)
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn chmod_keeps_files_readable_by_their_owner() {
    let dir = install_dir();
    for mode in [0, 0o200, 0o100, 0o377] {
        // A mode jtm could not read is a limit breach, so catching it does not help.
        let result = post_extract(
            dir.path(),
            &format!("pcall(jtm.fs.chmod, 'lib/nested/a.txt', {mode})"),
        );
        assert_eq!(
            limit_of(result),
            Limit::Mode {
                path: "lib/nested/a.txt".to_owned(),
                mode,
            },
            "{mode:#o}"
        );
    }
    post_extract(
        dir.path(),
        "jtm.fs.chmod('README', 256) jtm.fs.chmod('bin/tool', 365)",
    )
    .unwrap_or_else(|e| panic!("{e}"));
}

#[cfg(unix)]
#[test]
fn directories_the_hook_locks_get_their_owner_bits_back() {
    let dir = install_dir();
    let _unlock = Unlock(dir.path());
    post_extract(
        dir.path(),
        "jtm.fs.chmod('lib/nested', 0) jtm.fs.chmod('lib', 0) jtm.fs.chmod('.', 365)",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(mode_of(dir.path()), 0o755);
    assert_eq!(mode_of(&dir.path().join("lib")), 0o700);
    assert_eq!(mode_of(&dir.path().join("lib/nested")), 0o700);
    // A hook that fails after locking a directory leaves one jtm can still remove.
    let failed = post_extract(dir.path(), "jtm.fs.chmod('lib', 0) error('boom')");
    assert!(
        matches!(failed, Err(ScriptError::Failed { .. })),
        "{failed:?}"
    );
    assert_eq!(mode_of(&dir.path().join("lib")), 0o700);
}

#[cfg(unix)]
#[test]
fn locking_a_directory_cannot_hide_a_link_moved_outside() {
    let dir = install_dir();
    let _unlock = Unlock(dir.path());
    // `lib/nested/up` points at the root; moved up into `lib`, it points above the root.
    std::os::unix::fs::symlink("../..", dir.path().join("lib/nested/up"))
        .unwrap_or_else(|e| panic!("{e}"));
    for lock in ["jtm.fs.chmod('lib', 0)", "jtm.fs.chmod('.', 73)"] {
        let result = post_extract(
            dir.path(),
            &format!("jtm.fs.rename('lib/nested/up', 'lib/up') {lock}"),
        );
        match limit_of(result) {
            Limit::Path { path, reason } => {
                assert_eq!(path, "lib/up", "{lock}: {reason}");
                assert!(
                    reason.contains("outside the install dir"),
                    "{lock}: {reason}"
                );
            }
            other => panic!("{lock}: expected a containment failure, got {other:?}"),
        }
        fs::rename(dir.path().join("lib/up"), dir.path().join("lib/nested/up"))
            .unwrap_or_else(|e| panic!("{e}"));
    }
}

#[cfg(unix)]
#[test]
fn an_unreadable_directory_fails_the_link_check() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = install_dir();
    let _unlock = Unlock(dir.path());
    let hidden = dir.path().join("lib/nested");
    std::os::unix::fs::symlink("../../..", hidden.join("escape")).unwrap_or_else(|e| panic!("{e}"));
    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o000))
        .unwrap_or_else(|e| panic!("{e}"));
    let readable = fs::read_dir(&hidden).is_ok();
    // Without restoring modes first, so the check itself must fail closed.
    match super::fs::check_links(dir.path()) {
        Err(super::fs::Failure::Io { path, source }) if !readable => {
            assert_eq!(path, hidden);
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        // Running as root, permissions do not stop the read; the escaping link is found.
        Err(super::fs::Failure::Limit(Limit::Path { path, reason })) if readable => {
            assert_eq!(path, "lib/nested/escape", "{reason}");
            assert!(reason.contains("outside the install dir"), "{reason}");
        }
        other => panic!("readable: {readable}, got {other:?}"),
    }
}

#[test]
fn catching_a_memory_breach_does_not_help() {
    for source in [
        "function f() pcall(string.rep, 'x', 64 * 1024 * 1024) return '1' end",
        "function f() pcall(function() local t = {} for i = 1, 1e9 do t[i] = string.rep('x', 4096) .. i end end) return '1' end",
        "function f() xpcall(function() return string.rep('x', 64 * 1024 * 1024) end, function(e) return e end) return '1' end",
        // A handler that raises again must not replace the breach with its own error.
        "function f() xpcall(function() return string.rep('x', 64 * 1024 * 1024) end, function(e) error('hidden') end) return '1' end",
        "function f() pcall(xpcall, function() return string.rep('x', 64 * 1024 * 1024) end, function(e) error({}) end) return '1' end",
        // Running out of memory in the handler is a breach too.
        "function f() xpcall(function() error('x') end, function(e) return string.rep('x', 64 * 1024 * 1024) end) return '1' end",
        // So is one caught by nested protected calls.
        "function f() pcall(pcall, pcall, string.rep, 'x', 64 * 1024 * 1024) return '1' end",
        "function f() xpcall(pcall, function(e) return e end, string.rep, 'x', 64 * 1024 * 1024) return '1' end",
    ] {
        let limit = limit_of(tight(source).format_interop("f", "f", "v", "1"));
        assert!(matches!(limit, Limit::Memory(_)), "{source}: {limit:?}");
    }
    // And one in a host function. Building and decoding the text takes long enough on a slow
    // runner to pass a tight deadline first, so this case gets more time.
    let source = "function f() local text = '[' .. string.rep('0,', 1000000) .. '0]' \
                  pcall(jtm.json.decode, text) return '1' end";
    let limit = limit_of(
        script(source)
            .with_limits(Limits {
                memory: 8 * 1024 * 1024,
                time: Duration::from_secs(30),
            })
            .format_interop("f", "f", "v", "1"),
    );
    assert!(matches!(limit, Limit::Memory(_)), "{limit:?}");
}

#[test]
fn the_out_of_memory_message_alone_is_not_a_breach() {
    assert_eq!(
        ok(
            "local okay, err = pcall(error, 'not enough memory', 0) return tostring(okay) .. ' ' .. err"
        ),
        "false not enough memory"
    );
    assert_eq!(
        ok(
            "local okay, err = xpcall(function() error('not enough memory', 0) end, function(e) return e end) \
             return tostring(okay) .. ' ' .. err"
        ),
        "false not enough memory"
    );
    assert_eq!(
        ok(
            "local okay, err = xpcall(error, function(e) error('not enough memory', 0) end, 'x') \
             return tostring(okay) .. ' ' .. err"
        ),
        "false error in error handling"
    );
}

#[test]
fn an_xpcall_handler_does_not_run_after_a_memory_breach() {
    let dir = install_dir();
    let result = post_extract(
        dir.path(),
        "xpcall(function() return string.rep('x', 512 * 1024 * 1024) end, function(e) jtm.fs.remove('README') end)",
    );
    assert!(matches!(limit_of(result), Limit::Memory(_)));
    assert!(dir.path().join("README").is_file());
}

#[test]
fn pcall_and_xpcall_need_their_arguments() {
    assert_eq!(ok("return tostring(pcall(pcall))"), "false");
    assert_eq!(ok("return tostring(pcall(xpcall, error))"), "false");
    assert_eq!(ok("return tostring(pcall(xpcall, error, 42))"), "false");
}

#[test]
fn a_caught_containment_error_is_a_message_and_still_fails_the_hook() {
    let dir = install_dir();
    // The script removes README only if a handler saw something other than a string.
    let result = post_extract(
        dir.path(),
        "local a, b \
         xpcall(jtm.fs.remove, function(e) a = type(e) end, '../victim') \
         local _, e = pcall(jtm.fs.remove, '../victim') b = type(e) \
         if a ~= 'string' or b ~= 'string' then jtm.fs.remove('README') end",
    );
    assert!(is_path_limit(result));
    assert!(dir.path().join("README").is_file());
}

#[test]
fn a_memory_breach_after_another_limit_still_stops_the_script() {
    let dir = install_dir();
    let result = post_extract(
        dir.path(),
        "pcall(jtm.fs.remove, '../victim') \
         xpcall(function() return string.rep('x', 512 * 1024 * 1024) end, function(e) error('hidden') end) \
         jtm.fs.remove('README')",
    );
    assert!(is_path_limit(result));
    assert!(dir.path().join("README").is_file());
}

#[test]
fn pcall_and_xpcall_still_catch_ordinary_errors() {
    assert_eq!(
        ok(
            "local okay, err = pcall(error, 'boom') return tostring(okay) .. ' ' .. tostring(err:find('boom') ~= nil)"
        ),
        "false true"
    );
    assert_eq!(
        ok(
            "local okay, v = pcall(function(a) return a .. '!' end, 'hi') return tostring(okay) .. ' ' .. v"
        ),
        "true hi!"
    );
    assert_eq!(
        ok(
            "local okay, v = xpcall(function() error('x') end, function(e) return 'handled' end) return tostring(okay) .. ' ' .. v"
        ),
        "false handled"
    );
}

#[test]
fn pcall_and_xpcall_take_any_value_like_lua() {
    // A value that cannot be called is an ordinary caught error.
    assert_eq!(
        ok("local okay, err = pcall(nil) return tostring(okay) .. ' ' .. type(err)"),
        "false string"
    );
    assert_eq!(
        ok("local okay = pcall(42, 'x') return tostring(okay)"),
        "false"
    );
    // A callable table is called.
    assert_eq!(
        ok(
            "local t = setmetatable({}, { __call = function(_, x) return x * 2 end }) \
             local okay, v = pcall(t, 21) return tostring(okay) .. ' ' .. v"
        ),
        "true 42"
    );
    // An error value that is not a string reaches the script unchanged.
    assert_eq!(
        ok("local okay, err = pcall(error, { code = 7 }) return tostring(okay) .. ' ' .. err.code"),
        "false 7"
    );
    assert_eq!(
        ok(
            "local okay, v = xpcall(function() error({ code = 8 }) end, function(e) return e.code end) \
             return tostring(okay) .. ' ' .. v"
        ),
        "false 8"
    );
    // A host error is still seen as its message.
    assert_eq!(
        ok(
            "local okay, err = pcall(jtm.json.decode, '{') return type(err) .. ' ' .. tostring(err:find('invalid JSON') ~= nil)"
        ),
        "string true"
    );
}
