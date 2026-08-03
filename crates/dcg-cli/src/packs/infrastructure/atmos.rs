//! Atmos patterns - protections against destructive Atmos CLI operations.
//!
//! [Atmos](https://atmos.tools) (from Cloud Posse) is a CLI that orchestrates
//! Terraform/OpenTofu and Helmfile across "stacks" and "components". It wraps
//! those tools but adds its *own* verbs, so a command like
//! `atmos terraform deploy …` is a real, destructive operation whose string
//! contains no token that any `infrastructure.terraform` rule matches. This
//! pack closes the three Atmos-specific gaps the terraform pack cannot reach,
//! plus mirrors the terraform pack's coverage for the `atmos terraform <verb>`
//! pass-through verbs (so an Atmos user is protected even when the terraform
//! pack is not enabled):
//!
//! - `atmos terraform deploy` -> Atmos rewrites `deploy` to `apply` and INJECTS
//!   `-auto-approve`, so it applies with no confirmation. Equivalent risk to
//!   `terraform apply -auto-approve` (High) but the string says `deploy`.
//! - `atmos terraform clean [--everything] [--force]` -> deletes `.terraform/`,
//!   generated varfiles, backend config, and (with `--everything`) local state.
//! - `atmos helmfile destroy` -> removes Helm releases (the string contains
//!   `helmfile`, not `terraform`/`tofu`, so no terraform rule matches it).
//!
//! ## Self-contained
//!
//! The pack does not rely on `infrastructure.terraform` being enabled. An Atmos
//! repo keeps its `.tf` files nested under `components/terraform/<name>/`, so the
//! terraform pack's project auto-detection (which looks for root `*.tf`) often
//! does not fire. When both packs ARE enabled the overlap is harmless: the first
//! matching pattern wins and both assign the same severities.
//!
//! ## Matching design
//!
//! Like the terraform pack, destructive rules put a lazy `.*?` between the
//! `atmos` keyword, the tool word, and the verb so global flags - including
//! quoted multi-word values such as `--base-path './my dir'` - cannot defeat the
//! match. Two deliberate refinements over a naive `\bverb\b` make this pack
//! precise for Atmos's larger command surface:
//!
//! 1. **Verbs are anchored on a whitespace boundary (`\s<verb>`), not `\b`.**
//!    Atmos has a `workflow` subcommand whose argument is an arbitrary
//!    user-chosen name. A workflow named `terraform-deploy`
//!    (`atmos workflow terraform-deploy`) would, under a `\bdeploy` anchor,
//!    false-match the deploy rule because the `-` in `terraform-deploy` is a
//!    `\b` word boundary. Requiring whitespace immediately before the verb means
//!    only a verb that is its own CLI token matches, so hyphenated names and the
//!    `-destroy`/`-auto-approve` *flags* never trip the subcommand rules.
//! 2. **Read-only subcommands are whitelisted first** (Atmos evaluates safe
//!    patterns before destructive ones). The safe `plan`/`apply` patterns carry
//!    negative lookaheads so `plan -destroy` and `apply -auto-approve` fall
//!    through to their destructive rules, while a component literally named like
//!    a destructive verb (e.g. `atmos terraform plan deploy -s prod`) stays
//!    allowed - the verb is not in the subcommand slot.
//!
//! OpenTofu under Atmos is selected via `atmos.yaml`
//! (`components.terraform.command: tofu`) yet is still invoked as
//! `atmos terraform …`; the `tofu`/`opentofu`/`tf` tokens are accepted
//! defensively so every rule covers them identically. Interactive
//! `atmos terraform apply` (no `-auto-approve`) is intentionally allowed,
//! matching the terraform pack's philosophy for the underlying tool.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Atmos pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "infrastructure.atmos".to_string(),
        name: "Atmos",
        description: "Protects against destructive Atmos operations like terraform deploy \
                      (auto-approve), destroy, clean, state rm/taint, and helmfile destroy",
        keywords: &["atmos"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // Whitelist read-only subcommands. The `(?:\s+--?\S+(?:\s+\S+)?)*` fragments
    // skip optional global flags after `atmos` and after the tool word, and the
    // subcommand is anchored to its slot with `(?=\s|$)` so a component named
    // like a verb is not whitelisted by accident. These are evaluated BEFORE the
    // destructive rules (see `Pack::check`), so a safe subcommand carrying a
    // verb-like component (e.g. `atmos terraform plan deploy`) is allowed rather
    // than tripping a destructive rule.
    vec![
        // plan is safe (read-only) - but NOT `plan -destroy` (handled below).
        safe_pattern!(
            "atmos-terraform-plan",
            r"atmos\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:terraform|tofu|opentofu|tf)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+plan(?=\s|$)(?!\s+.*-destroy)"
        ),
        // Interactive apply is safe (mirrors the terraform pack) - but NOT
        // `apply -auto-approve` (handled by the destructive rule below). This
        // also keeps a component literally named like a verb
        // (`atmos terraform apply deploy -s prod`) allowed.
        safe_pattern!(
            "atmos-terraform-apply",
            r"atmos\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:terraform|tofu|opentofu|tf)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+apply(?=\s|$)(?!\s+.*-auto-approve)"
        ),
        // output is safe (read-only)
        safe_pattern!(
            "atmos-terraform-output",
            r"atmos\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:terraform|tofu|opentofu|tf)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+output(?=\s|$)"
        ),
        // validate is safe (read-only)
        safe_pattern!(
            "atmos-terraform-validate",
            r"atmos\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:terraform|tofu|opentofu|tf)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+validate(?=\s|$)"
        ),
        // describe is safe (read-only inspection of stacks/components/config)
        safe_pattern!(
            "atmos-describe",
            r"atmos\b(?:\s+--?\S+(?:\s+\S+)?)*\s+describe\b"
        ),
        // helmfile diff is safe (read-only)
        safe_pattern!(
            "atmos-helmfile-diff",
            r"atmos\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:helmfile|hf)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+diff(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // plan -destroy is a read-only preview but worth surfacing. Keep BEFORE
        // the broader destroy rule so the preview keeps its Medium severity
        // (mirrors the terraform pack ordering).
        destructive_pattern!(
            "atmos-plan-destroy",
            r"atmos\b.*?\b(?:terraform|tofu|opentofu|tf)\b.*?\splan\s+.*-destroy",
            "atmos terraform plan -destroy previews destruction. Review carefully before deploying.",
            Medium,
            "atmos terraform plan -destroy shows a destruction preview:\n\n\
             - Read-only (safe to run), but shows what WOULD be destroyed\n\
             - Review the output carefully before applying/deploying\n\n\
             This is the safe way to preview a destroy."
        ),
        // destroy tears down all managed infrastructure for the component/stack.
        destructive_pattern!(
            "atmos-destroy",
            r"atmos\b.*?\b(?:terraform|tofu|opentofu|tf)\b.*?\sdestroy(?=\s|$)",
            "atmos terraform destroy removes ALL managed infrastructure for the component/stack.",
            Critical,
            "atmos terraform destroy removes managed infrastructure:\n\n\
             - Every resource in the component's state is destroyed\n\
             - --affected / --all destroy across MANY components at once\n\
             - Cannot be undone without backups/recreation\n\n\
             Preview first: atmos terraform plan -destroy <component> -s <stack>"
        ),
        // deploy = apply -auto-approve. Atmos rewrites `deploy` to `apply` and
        // injects -auto-approve, so it never reaches the apply-auto-approve rule.
        destructive_pattern!(
            "atmos-deploy",
            r"atmos\b.*?\b(?:terraform|tofu|opentofu|tf)\b.*?\sdeploy(?=\s|$)",
            "atmos terraform deploy runs apply with -auto-approve (no confirmation). Preview with 'atmos terraform plan' first.",
            High,
            "atmos terraform deploy auto-approves an apply:\n\n\
             - Atmos rewrites 'deploy' to 'apply' and injects -auto-approve\n\
             - Changes are applied immediately, with no confirmation prompt\n\
             - May destroy or recreate resources\n\n\
             Preview first: atmos terraform plan <component> -s <stack>"
        ),
        // explicit apply -auto-approve (Atmos passes flags through to terraform).
        destructive_pattern!(
            "atmos-apply-auto-approve",
            r"atmos\b.*?\b(?:terraform|tofu|opentofu|tf)\b.*?\sapply\s+.*-auto-approve",
            "atmos terraform apply -auto-approve skips confirmation. Remove -auto-approve for safety.",
            High,
            "atmos terraform apply -auto-approve skips confirmation:\n\n\
             - No opportunity to review the plan before applying\n\
             - Intended for CI/CD, not interactive use\n\
             - Changes may destroy or recreate resources\n\n\
             For safety: drop -auto-approve and review the plan"
        ),
        // clean deletes local Terraform state and generated files.
        destructive_pattern!(
            "atmos-clean",
            r"atmos\b.*?\b(?:terraform|tofu|opentofu|tf)\b.*?\sclean(?=\s|$)",
            "atmos terraform clean deletes local Terraform state and generated files (.terraform/, varfiles, backend config; --everything also removes terraform.tfstate*).",
            High,
            "atmos terraform clean removes local Terraform working files:\n\n\
             - Deletes .terraform/, generated varfiles, and backend config\n\
             - --everything also removes local state (terraform.tfstate*)\n\
             - --force skips the confirmation prompt\n\
             - Back up any local-only state before running\n\n\
             Inspect what would be removed before using --everything --force"
        ),
        // taint marks a resource for recreation on next apply.
        destructive_pattern!(
            "atmos-taint",
            r"atmos\b.*?\b(?:terraform|tofu|opentofu|tf)\b.*?\staint\b",
            "atmos terraform taint marks a resource to be destroyed and recreated on next apply.",
            High,
            "atmos terraform taint marks a resource for recreation:\n\n\
             - The resource is destroyed and recreated on next apply/deploy\n\
             - May cause downtime; identifiers/IPs may change\n\n\
             Prefer -replace in plan/apply (Terraform 0.15.2+)"
        ),
        // state rm removes a resource from state (orphans the real resource).
        destructive_pattern!(
            "atmos-state-rm",
            r"atmos\b.*?\b(?:terraform|tofu|opentofu|tf)\b.*?\sstate\s+rm\b",
            "atmos terraform state rm removes a resource from state without destroying it. Resource becomes unmanaged.",
            High,
            "atmos terraform state rm orphans a resource:\n\n\
             - Removed from Terraform state, but the cloud resource remains\n\
             - The resource becomes unmanaged (Terraform ignores it)\n\
             - May cause drift between state and reality\n\n\
             Back up state first (atmos terraform state pull)"
        ),
        // state mv can recreate resources if done incorrectly.
        destructive_pattern!(
            "atmos-state-mv",
            r"atmos\b.*?\b(?:terraform|tofu|opentofu|tf)\b.*?\sstate\s+mv\b",
            "atmos terraform state mv moves resources in state. Incorrect moves can cause resource recreation.",
            High,
            "atmos terraform state mv rewrites resource addresses:\n\n\
             - A wrong move can cause destruction/recreation\n\
             - Does not affect the actual cloud resources\n\n\
             Preview the move and back up state first"
        ),
        // force-unlock removes a state lock.
        destructive_pattern!(
            "atmos-force-unlock",
            r"atmos\b.*?\b(?:terraform|tofu|opentofu|tf)\b.*?\sforce-unlock\b",
            "atmos terraform force-unlock removes a state lock. Only use if the lock is stale.",
            High,
            "atmos terraform force-unlock removes a state lock:\n\n\
             - May corrupt state if another operation is in progress\n\
             - Only use when you are sure no other run is active\n\n\
             Verify no other operations: CI/CD pipelines, other operators"
        ),
        // workspace delete removes a workspace and its state.
        destructive_pattern!(
            "atmos-workspace-delete",
            r"atmos\b.*?\b(?:terraform|tofu|opentofu|tf)\b.*?\sworkspace\s+delete\b",
            "atmos terraform workspace delete removes a workspace and its state.",
            Medium,
            "atmos terraform workspace delete removes a workspace:\n\n\
             - The workspace and its state file are deleted\n\
             - Does NOT destroy actual infrastructure (resources orphaned)\n\n\
             Destroy resources first, then delete the workspace"
        ),
        // helmfile destroy removes Helm releases from the cluster. The command
        // contains `helmfile`, not `terraform`, so no terraform rule reaches it.
        destructive_pattern!(
            "atmos-helmfile-destroy",
            r"atmos\b.*?\b(?:helmfile|hf)\b.*?\sdestroy(?=\s|$)",
            "atmos helmfile destroy removes Helm releases from the cluster.",
            Critical,
            "atmos helmfile destroy tears down Helm releases:\n\n\
             - Deletes the component's Helm releases from the cluster\n\
             - Workloads, services, and their data may be removed\n\
             - Cannot be undone without redeploying\n\n\
             Inspect first: atmos helmfile diff <component> -s <stack>"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn atmos_blocks_atmos_specific_verbs() {
        let pack = create_pack();
        // deploy = apply -auto-approve, the core #168 gap.
        assert_blocks(&pack, "atmos terraform deploy vpc -s prod", "auto-approve");
        // deploy with no component (whole-stack) and mass deploy.
        assert_blocks(&pack, "atmos terraform deploy", "auto-approve");
        assert_blocks(&pack, "atmos terraform deploy --affected", "auto-approve");
        // clean deletes local state/artifacts.
        assert_blocks(
            &pack,
            "atmos terraform clean",
            "deletes local Terraform state",
        );
        assert_blocks(
            &pack,
            "atmos terraform clean --everything --force",
            "deletes local Terraform state",
        );
        // helmfile destroy (no terraform token in the string).
        assert_blocks(&pack, "atmos helmfile destroy app -s prod", "Helm releases");
        assert_blocks(&pack, "atmos hf destroy app -s prod", "Helm releases");
    }

    #[test]
    fn atmos_blocks_terraform_passthrough_verbs_standalone() {
        // The pack is self-contained: these must block even if the terraform
        // pack is disabled (an Atmos repo often won't auto-enable it).
        let pack = create_pack();
        assert_blocks(&pack, "atmos terraform destroy vpc -s prod", "destroy");
        assert_blocks(
            &pack,
            "atmos terraform plan -destroy vpc -s prod",
            "plan -destroy",
        );
        assert_blocks(
            &pack,
            "atmos terraform apply -auto-approve vpc -s prod",
            "auto-approve",
        );
        assert_blocks(
            &pack,
            "atmos terraform taint vpc -s prod aws_instance.x",
            "taint",
        );
        assert_blocks(
            &pack,
            "atmos terraform state rm vpc -s prod aws_s3_bucket.data",
            "state rm",
        );
        assert_blocks(
            &pack,
            "atmos terraform state mv vpc -s prod a b",
            "state mv",
        );
        assert_blocks(
            &pack,
            "atmos terraform force-unlock vpc -s prod abc123",
            "force-unlock",
        );
        assert_blocks(
            &pack,
            "atmos terraform workspace delete old-workspace",
            "workspace delete",
        );
    }

    #[test]
    fn atmos_blocks_with_correct_severity() {
        let pack = create_pack();
        // The #168 trio.
        assert_blocks_with_severity(&pack, "atmos terraform deploy vpc -s prod", Severity::High);
        assert_blocks_with_severity(&pack, "atmos terraform clean", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "atmos helmfile destroy app -s prod",
            Severity::Critical,
        );
        // Pass-through parity with the terraform pack.
        assert_blocks_with_severity(
            &pack,
            "atmos terraform destroy vpc -s prod",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "atmos terraform plan -destroy vpc -s prod",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "atmos terraform apply -auto-approve vpc",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "atmos terraform taint vpc -s prod aws_instance.x",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "atmos terraform workspace delete dev",
            Severity::Medium,
        );
    }

    #[test]
    fn atmos_blocks_with_correct_pattern_names() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "atmos terraform deploy vpc -s prod", "atmos-deploy");
        assert_blocks_with_pattern(&pack, "atmos terraform clean --force", "atmos-clean");
        assert_blocks_with_pattern(
            &pack,
            "atmos helmfile destroy app -s prod",
            "atmos-helmfile-destroy",
        );
        assert_blocks_with_pattern(
            &pack,
            "atmos terraform destroy vpc -s prod",
            "atmos-destroy",
        );
        // plan -destroy keeps its own (Medium) rule, not the destroy rule.
        assert_blocks_with_pattern(
            &pack,
            "atmos terraform plan -destroy vpc -s prod",
            "atmos-plan-destroy",
        );
    }

    #[test]
    fn atmos_tofu_and_aliases_have_parity() {
        // OpenTofu under Atmos normally rides through `atmos terraform …`
        // (selected via atmos.yaml), but the tool tokens are accepted so every
        // rule covers them identically.
        let pack = create_pack();
        assert_blocks(&pack, "atmos tofu deploy vpc -s prod", "auto-approve");
        assert_blocks(&pack, "atmos tofu destroy vpc -s prod", "destroy");
        assert_blocks(
            &pack,
            "atmos tofu clean --everything --force",
            "deletes local Terraform state",
        );
        assert_blocks(&pack, "atmos opentofu deploy vpc -s prod", "auto-approve");
        assert_blocks(&pack, "atmos tf destroy vpc -s prod", "destroy");
        // Severity parity.
        assert_blocks_with_severity(&pack, "atmos tofu destroy vpc -s prod", Severity::Critical);
        assert_blocks_with_severity(&pack, "atmos tofu deploy vpc -s prod", Severity::High);
        // Read-only and interactive apply stay allowed for tofu too.
        assert_allows(&pack, "atmos tofu plan vpc -s prod");
        assert_allows(&pack, "atmos tofu apply vpc -s prod");
        assert_allows(&pack, "atmos tofu output vpc -s prod");
    }

    #[test]
    fn atmos_quoted_multiword_flag_does_not_bypass() {
        // A quoted, space-containing global-flag value must not let a destructive
        // subcommand escape (the destructive rules use a loose `.*?`).
        let pack = create_pack();
        assert_blocks(
            &pack,
            "atmos --base-path './my long dir' terraform clean vpc -s prod",
            "deletes local Terraform state",
        );
        assert_blocks(
            &pack,
            "atmos --logs-level 'Trace and more' terraform deploy vpc -s prod",
            "auto-approve",
        );
    }

    #[test]
    fn atmos_allows_read_only_and_interactive_apply() {
        let pack = create_pack();
        // Interactive apply (no -auto-approve) is intentionally allowed,
        // mirroring the terraform pack.
        assert_allows(&pack, "atmos terraform apply vpc -s prod");
        assert_allows(&pack, "atmos terraform plan vpc -s prod");
        assert_allows(&pack, "atmos terraform output vpc -s prod");
        assert_allows(&pack, "atmos terraform validate vpc -s prod");
        assert_allows(&pack, "atmos describe stacks");
        assert_allows(&pack, "atmos describe component vpc -s prod");
        assert_allows(&pack, "atmos helmfile diff app -s prod");
    }

    #[test]
    fn atmos_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "atmos terraform plan vpc -s prod");
        assert_safe_pattern_matches(&pack, "atmos terraform apply vpc -s prod");
        assert_safe_pattern_matches(&pack, "atmos terraform output vpc -s prod");
        assert_safe_pattern_matches(&pack, "atmos terraform validate vpc -s prod");
        assert_safe_pattern_matches(&pack, "atmos describe component vpc -s prod");
        assert_safe_pattern_matches(&pack, "atmos helmfile diff app -s prod");
    }

    #[test]
    fn atmos_component_named_like_verb_does_not_bypass() {
        // A read-only subcommand with a component named like a destructive verb
        // is whitelisted by the safe pattern (checked first), so it stays
        // ALLOWED - the verb is not in the subcommand slot.
        let pack = create_pack();
        assert_allows(&pack, "atmos terraform plan deploy -s prod");
        assert_allows(&pack, "atmos terraform plan clean -s prod");
        assert_allows(&pack, "atmos terraform output destroy -s prod");
        // Interactive apply with a verb-named component is allowed because the
        // safe apply pattern (no -auto-approve) matches first.
        assert_allows(&pack, "atmos terraform apply deploy -s prod");
        assert_allows(&pack, "atmos terraform apply destroy -s prod");
    }

    #[test]
    fn atmos_workflow_and_hyphenated_names_do_not_false_match() {
        // Atmos `workflow` takes an arbitrary user-chosen name. A name that
        // happens to contain a tool word and a verb (e.g. `terraform-deploy`)
        // must NOT trip a destructive rule - the verb is anchored on whitespace,
        // so a hyphen-joined name is not a standalone subcommand token.
        let pack = create_pack();
        assert_allows(&pack, "atmos workflow deploy-all");
        assert_allows(&pack, "atmos workflow terraform-deploy");
        assert_allows(&pack, "atmos workflow terraform-destroy -f deploy.yaml");
        assert_allows(&pack, "atmos workflow helmfile-destroy");
        assert_allows(&pack, "atmos workflow deploy-terraform");
    }

    #[test]
    fn atmos_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "echo atmos");
        assert_no_match(&pack, "atmos version");
        assert_no_match(&pack, "atmos vendor pull");
        assert_no_match(&pack, "git status");
    }

    #[test]
    fn atmos_pack_definition_is_valid() {
        let pack = create_pack();
        validate_pack(&pack);
    }
}
