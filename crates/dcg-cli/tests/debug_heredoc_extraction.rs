#[cfg(test)]
mod tests {
    use dcg_cli::heredoc::extract_shell_commands;

    #[test]
    fn test_extract_clean_command() {
        // Case 1: unquoted redirection
        // tree-sitter-bash wraps the redirect in a `redirected_statement`
        // node; since #271 the complete statement is emitted first (so the
        // redirect target stays visible to the recursive evaluation) and the
        // bare command node follows.
        let cmds = extract_shell_commands("git >/dev/null reset --hard");
        assert!(!cmds.is_empty(), "should extract at least one command");
        println!("Unquoted: '{}'", cmds[0].text);
        assert_eq!(
            cmds[0].text, "git >/dev/null reset --hard",
            "the redirected statement must be surfaced completely"
        );
        assert!(
            cmds.iter()
                .any(|cmd| cmd.text == "git reset --hard" || cmd.text == "git"),
            "the bare command node is still collected: {cmds:?}"
        );

        // Case 2: quoted redirection
        let cmds = extract_shell_commands("\"git\">/dev/null reset --hard");
        assert!(!cmds.is_empty(), "should extract at least one command");
        println!("Quoted: '{}'", cmds[0].text);
        // Note: ast-grep might keep quotes around "git"
        // If it returns "git" reset --hard", that's fine, normalization dequotes it later.
        // But we passed `cmd.text` as `normalized` too in evaluator.
        // So `evaluate_packs` sees `"git" reset --hard`.
        // Does regex match `"git"`?
        // `core.git` regex: `(?:^|[ |||;&])git\s+`.
        // It expects `git` (unquoted).
        // If `cmd.text` has quotes, regex fails!
    }
}
