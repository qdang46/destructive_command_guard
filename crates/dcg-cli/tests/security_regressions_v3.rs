#[cfg(test)]
mod tests {
    use dcg_cli::config::Config;
    use dcg_cli::evaluator::evaluate_command;
    use dcg_cli::load_default_allowlists;
    use dcg_cli::packs::REGISTRY;

    fn get_eval_components() -> (
        Config,
        Vec<&'static str>,
        dcg_cli::config::CompiledOverrides,
        dcg_cli::allowlist::LayeredAllowlist,
    ) {
        let config = Config::default();
        let enabled_packs = config.enabled_pack_ids();
        let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
        let compiled = config.overrides.compile();
        let allowlists = load_default_allowlists();
        (config, enabled_keywords, compiled, allowlists)
    }

    #[test]
    fn test_backslash_quoted_data_sink_heredoc_is_inert() {
        let (config, keywords, compiled, allowlists) = get_eval_components();

        // Backslash-quoting the delimiter suppresses shell expansion. Since the
        // receiver is the real `cat` data sink, the body is inert data and must
        // not become a false positive merely because it contains destructive
        // command text.
        let cmd = r"
cat <<\EOF
rm -rf /
EOF
";
        let result = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);
        assert!(
            !result.is_denied(),
            "quoted data-sink heredoc should remain inert: {cmd}"
        );

        // The same delimiter syntax must never hide an executing heredoc. A
        // visible shell function can replace `cat` and execute the body, so
        // data-sink masking must fail closed in this form.
        let executing = r"
cat() { bash -s; }
cat <<\EOF
rm -rf /
EOF
";
        let result = evaluate_command(executing, &config, &keywords, &compiled, &allowlists);
        assert!(
            result.is_denied(),
            "backslash-quoted heredoc executed by a shell function must be blocked: {executing}"
        );
    }

    #[test]
    fn test_command_internal_escape_bypass() {
        let (config, keywords, compiled, allowlists) = get_eval_components();

        // Bash treats "g\it" exactly like "git".
        // If normalization doesn't handle this, regexes looking for "\bgit\b" will fail.
        let cmd = r"g\it reset --hard";
        let result = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);
        assert!(
            result.is_denied(),
            "Should block command with internal backslash escaping: {cmd}"
        );
    }

    #[test]
    fn test_command_mixed_quoting_bypass() {
        let (config, keywords, compiled, allowlists) = get_eval_components();

        // Bash treats "g'i't" exactly like "git".
        let cmd = r"g'i't reset --hard";
        let result = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);
        assert!(
            result.is_denied(),
            "Should block command with mixed quoting: {cmd}"
        );
    }
}
