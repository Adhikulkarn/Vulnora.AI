"""
Command-line interface for Vulnora AI.

Provides CLI entry points for:
- `vulnora init`: Initialize Vulnora configuration, git hooks, and .gitignore.
- `vulnora status` / `vulnora check-git`: Inspect Git status, protected branches, and repository diagnostics.
- `vulnora scan`: Run multi-scanner detection pipeline (diff-scoped or full scan, DAST via target URL).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional
import os
import vulnora
from vulnora.core.config import (
    get_config_path,
    get_vulnora_dir,
    init_config,
    load_config,
)
from vulnora.core.git_engine import GitEngine, GitEngineError
from vulnora.core.models import Finding, RemediationProposal, Severity
from vulnora.engine.cloud_ai import CloudAIClient, CloudAIError
from vulnora.engine.mcp_server import VulnoraMCPServer
from vulnora.engine.prompt_compiler import SurgicalPromptCompiler
from vulnora.engine.verifier import FixVerifier
from vulnora.immune.antibody_pack import AntibodyPackError, AntibodyPackManager
from vulnora.immune.memory_store import ImmuneMemoryStore
from vulnora.scanners.runner import ScannerOrchestrator


def build_parser() -> argparse.ArgumentParser:
    """Constructs the command-line argument parser for Vulnora CLI."""
    parser = argparse.ArgumentParser(
        prog="vulnora",
        description="Vulnora AI — Autonomous, language-agnostic security guard and self-vaccinating codebase engine.",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"%(prog)s {vulnora.__version__}",
    )
    parser.add_argument(
        "--repo-dir",
        "-C",
        type=str,
        default=None,
        help="Path to target Git repository (default: current directory).",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: init
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize Vulnora configuration, .gitignore rules, and Git hooks.",
    )
    init_parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Overwrite existing .vulnora/config.yaml.",
    )
    init_parser.add_argument(
        "--name",
        "-n",
        type=str,
        default=None,
        help="Override project name.",
    )
    init_parser.add_argument(
        "--no-hook",
        action="store_true",
        help="Skip installing the Git pre-push hook.",
    )

    # Command: status
    status_parser = subparsers.add_parser(
        "status",
        help="Display Git repository status, branch protection, and scanner diagnostics.",
    )
    status_parser.add_argument(
        "--json",
        action="store_true",
        help="Output diagnostics in JSON format.",
    )

    # Command: check-git (alias for status)
    check_git_parser = subparsers.add_parser(
        "check-git",
        help="Check Git environment and hook integration (alias for status).",
    )
    check_git_parser.add_argument(
        "--json",
        action="store_true",
        help="Output diagnostics in JSON format.",
    )

    # Command: scan (Phase 2 Detection Orchestrator)
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run multi-scanner security analysis across secrets, SAST, SCA, IaC, and DAST.",
    )
    scan_parser.add_argument(
        "--full",
        action="store_true",
        help="Perform a full repository scan instead of diff-scoped inspection.",
    )
    scan_parser.add_argument(
        "--target-url",
        type=str,
        default=None,
        help="Target web URL to activate dynamic application security testing (OWASP ZAP).",
    )
    scan_parser.add_argument(
        "--scanners",
        "-s",
        type=str,
        default=None,
        help="Comma-separated list of scanners to run (e.g. 'gitleaks,semgrep,bandit').",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Timeout in seconds for each individual scanner execution.",
    )
    scan_parser.add_argument(
        "--block",
        action="store_true",
        default=False,
        help="Exit with non-zero status code if critical or high findings are detected.",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings and metrics in JSON format.",
    )

    # Command: immune (Phase 3 Multi-Language AST Immune Memory & Antibody Packs)
    immune_parser = subparsers.add_parser(
        "immune",
        help="Inspect and manage local AST immune memory and antibody packs.",
    )
    immune_sub = immune_parser.add_subparsers(dest="immune_command", help="Immune subcommands")

    # immune stats
    stats_parser = immune_sub.add_parser("stats", help="Display immune memory metrics and hit rates.")
    stats_parser.add_argument("--json", action="store_true", help="Output metrics in JSON format.")

    # immune export
    export_parser = immune_sub.add_parser("export", help="Export sanitized antibody pack (JSON or YAML).")
    export_parser.add_argument("--output", "-o", type=str, default=None, help="Output file path (.json or .yaml).")
    export_parser.add_argument("--name", type=str, default="vulnora-antibodies", help="Pack name metadata.")
    export_parser.add_argument("--rules", type=str, default=None, help="Comma-separated rule IDs to export.")

    # immune import
    import_parser = immune_sub.add_parser("import", help="Import an antibody pack into local immune memory.")
    import_parser.add_argument("file", type=str, help="Path to antibody pack file (.json or .yaml).")
    import_parser.add_argument("--overwrite", action="store_true", help="Overwrite existing matching records.")

    # immune inspect
    inspect_parser = immune_sub.add_parser("inspect", help="Inspect stored antibodies and anonymized templates.")
    inspect_parser.add_argument("--json", action="store_true", help="Output records in JSON format.")
    inspect_parser.add_argument("--rule-id", type=str, default=None, help="Filter records by rule ID.")

    # Command: prompt (Phase 4 Surgical Fix-Prompt Compiler)
    prompt_parser = subparsers.add_parser(
        "prompt",
        help="Compile a surgical, zero-secret fix prompt for external AI coding agents.",
    )
    prompt_parser.add_argument(
        "--file",
        "-f",
        type=str,
        required=True,
        help="Target file path containing the vulnerability.",
    )
    prompt_parser.add_argument(
        "--line",
        "-l",
        type=int,
        default=None,
        help="Vulnerable line number in the target file.",
    )
    prompt_parser.add_argument(
        "--rule",
        "-r",
        type=str,
        default="CUSTOM-SECURITY-RULE",
        help="Security scanner rule ID or identifier.",
    )
    prompt_parser.add_argument(
        "--scanner",
        "-s",
        type=str,
        default="vulnora",
        help="Scanner name (default: vulnora).",
    )
    prompt_parser.add_argument(
        "--severity",
        type=str,
        default="HIGH",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Vulnerability severity level (default: HIGH).",
    )
    prompt_parser.add_argument(
        "--title",
        "-t",
        type=str,
        default=None,
        help="Short title or name of the vulnerability.",
    )
    prompt_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Output markdown file path to save the compiled prompt.",
    )
    prompt_parser.add_argument(
        "--json",
        action="store_true",
        help="Output compiled prompt metadata in JSON format.",
    )

    # Command: fix (Phase 5 Cloud AI Remediation & Verification Loop)
    fix_parser = subparsers.add_parser(
        "fix",
        help="Generate surgical Cloud AI patch, run automated single-scanner verification, and record antibody.",
    )
    fix_parser.add_argument(
        "--file",
        "-f",
        type=str,
        required=True,
        help="Target file path containing the vulnerability.",
    )
    fix_parser.add_argument(
        "--line",
        "-l",
        type=int,
        default=None,
        help="Vulnerable line number in the target file.",
    )
    fix_parser.add_argument(
        "--rule",
        "-r",
        type=str,
        default="CUSTOM-SECURITY-RULE",
        help="Flagging security rule ID (e.g. 'B605', 'CWE-89').",
    )
    fix_parser.add_argument(
        "--scanner",
        "-s",
        type=str,
        default="bandit",
        help="Flagging scanner name (e.g. 'bandit', 'semgrep', 'gitleaks').",
    )
    fix_parser.add_argument(
        "--severity",
        type=str,
        default="HIGH",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Vulnerability severity level.",
    )
    fix_parser.add_argument(
        "--provider",
        type=str,
        default=None,
        help="Cloud AI provider override ('gemini', 'groq', 'ollama', 'openai').",
    )
    fix_parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Model name override (e.g. 'gemini-2.5-flash', 'llama-3.3-70b-versatile').",
    )
    fix_parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="API key override for the Cloud AI provider.",
    )
    fix_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Timeout in seconds for Cloud AI inference (default from config or 60s).",
    )
    fix_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate deterministic mock patch without making network requests.",
    )
    fix_parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Output remediation proposal without applying patch or running verification loop.",
    )
    fix_parser.add_argument(
        "--json",
        action="store_true",
        help="Output remediation and verification details in JSON format.",
    )

    # Command: verify (Phase 5 Verification & Learning Loop)
    verify_parser = subparsers.add_parser(
        "verify",
        help="Re-run flagging scanner on target file, commit clean antibody to memory, and update AGENTS.md.",
    )
    verify_parser.add_argument(
        "--file",
        "-f",
        type=str,
        required=True,
        help="Target file path to verify.",
    )
    verify_parser.add_argument(
        "--scanner",
        "-s",
        type=str,
        default="bandit",
        help="Flagging scanner to re-run.",
    )
    verify_parser.add_argument(
        "--rule",
        "-r",
        type=str,
        required=True,
        help="Security rule ID to verify has been resolved.",
    )
    verify_parser.add_argument(
        "--rule-text",
        type=str,
        default=None,
        help="Preventative rule text to append to AGENTS.md upon clean verification.",
    )
    verify_parser.add_argument(
        "--json",
        action="store_true",
        help="Output verification result in JSON format.",
    )

    # Command: mcp (Phase 5 Local Model Context Protocol Server)
    mcp_parser = subparsers.add_parser(
        "mcp",
        help="Launch the local Model Context Protocol (MCP) stdio server for AI coding agents.",
    )
    mcp_parser.add_argument(
        "--stdio",
        action="store_true",
        default=True,
        help="Serve MCP over standard input/output (default).",
    )

    # Command: guard (Phase 6 Interactive Git Pre-Push Guard)
    guard_parser = subparsers.add_parser(
        "guard",
        help="Autonomous Git pre-push guard with interactive TUI or headless CI blocking.",
    )
    guard_parser.add_argument(
        "--hook",
        action="store_true",
        help="Invoked from Git pre-push hook (reads push refs from stdin).",
    )
    guard_parser.add_argument(
        "--full",
        action="store_true",
        help="Perform full repository scan instead of diff-scoped inspection.",
    )
    guard_parser.add_argument(
        "--block",
        action="store_true",
        default=True,
        help="Block push (exit 1) if critical or high severity vulnerabilities exist.",
    )
    guard_parser.add_argument(
        "--no-tui",
        action="store_true",
        help="Force headless non-interactive mode even if TTY is available.",
    )
    guard_parser.add_argument(
        "--target-url",
        type=str,
        default=None,
        help="Target URL for DAST scanning (OWASP ZAP).",
    )

    # Command: pack (Phase 6 Portable Antibody Pack Manager)
    pack_parser = subparsers.add_parser(
        "pack",
        help="Export and import portable, sanitized antibody packs across codebases.",
    )
    pack_sub = pack_parser.add_subparsers(dest="pack_command", help="Pack subcommands")

    # pack export
    pack_export = pack_sub.add_parser("export", help="Export sanitized antibody pack (JSON or YAML).")
    pack_export.add_argument("--output", "-o", type=str, default=None, help="Output file path (.json or .yaml).")
    pack_export.add_argument("--name", type=str, default="vulnora-antibodies", help="Pack name metadata.")
    pack_export.add_argument("--rules", type=str, default=None, help="Comma-separated rule IDs to export.")

    # pack import
    pack_import = pack_sub.add_parser("import", help="Import an antibody pack into local immune memory.")
    pack_import.add_argument("file", type=str, help="Path to antibody pack file (.json or .yaml).")
    pack_import.add_argument("--overwrite", action="store_true", help="Overwrite existing matching records.")

    # Command: hook (Git Hook Dispatcher)
    hook_parser = subparsers.add_parser("hook", help="Git hook entry points.")
    hook_sub = hook_parser.add_subparsers(dest="hook_type")
    hook_sub.add_parser("pre-push", help="Execute pre-push guard.")

    # Command: tui (Phase 6 Interactive Textual Dashboard)
    subparsers.add_parser("tui", help="Launch the interactive Textual TUI dashboard.")

    return parser


def handle_init(args: argparse.Namespace) -> int:
    """Handles `vulnora init` command."""
    target_dir = Path(args.repo_dir).resolve() if args.repo_dir else Path.cwd().resolve()
    engine = GitEngine(repo_path=target_dir)

    print(f"[*] Initializing Vulnora AI in: {target_dir}")

    # Step 1: Detect repository language
    lang_info = engine.detect_repository_languages()
    print(f"[*] Detected Primary Language: {lang_info.primary_language}")
    if lang_info.manifest_files:
        print(f"[*] Manifest files found: {', '.join(lang_info.manifest_files)}")

    # Step 2: Initialize configuration
    try:
        config_path = init_config(
            base_path=target_dir,
            project_name=args.name,
            language=lang_info.primary_language.lower(),
            force=args.force,
        )
        print(f"[+] Created configuration: {config_path}")
    except FileExistsError:
        print(f"[!] Configuration already exists at: {get_config_path(target_dir)}")
        print("    Use --force to overwrite.")
    except Exception as exc:
        print(f"[-] Error writing configuration: {exc}", file=sys.stderr)
        return 1

    # Step 3: Update .gitignore if inside a Git repo or directory
    try:
        added_entries = engine.update_gitignore()
        if added_entries:
            print(f"[+] Added to .gitignore: {', '.join(added_entries)}")
        else:
            print("[*] .gitignore already contains required Vulnora rules.")
    except Exception as exc:
        print(f"[!] Warning: Could not update .gitignore: {exc}", file=sys.stderr)

    # Step 4: Install Git hook
    if not args.no_hook:
        if engine.is_git_repository():
            try:
                hook_path = engine.install_pre_push_hook(force=args.force)
                print(f"[+] Installed pre-push Git hook: {hook_path}")
            except Exception as exc:
                print(f"[!] Warning: Could not install pre-push hook: {exc}", file=sys.stderr)
        else:
            print("[*] Target is not a Git repository; skipping pre-push hook installation.")

    print("\n[✔] Vulnora initialization complete!")
    return 0


def handle_status(args: argparse.Namespace) -> int:
    """Handles `vulnora status` and `vulnora check-git` commands."""
    target_dir = Path(args.repo_dir).resolve() if args.repo_dir else Path.cwd().resolve()
    engine = GitEngine(repo_path=target_dir)
    config = load_config(base_path=target_dir)

    is_installed = engine.is_git_installed()
    if not is_installed:
        if getattr(args, "json", False):
            print(json.dumps({"error": "Git executable not found in PATH", "git_installed": False}))
        else:
            print("[-] Error: 'git' executable was not found in PATH.", file=sys.stderr)
        return 1

    repo_status = engine.get_repo_status(protected_branches=config.git.protected_branches)
    lang_info = engine.detect_repository_languages()

    if getattr(args, "json", False):
        output = {
            "version": vulnora.__version__,
            "git_installed": True,
            "repository": repo_status.to_dict(),
            "languages": lang_info.to_dict(),
            "config": {
                "config_path": str(get_config_path(target_dir)),
                "config_exists": get_config_path(target_dir).exists(),
                "protected_branches": config.git.protected_branches,
                "enabled_scanners": config.scanners.enabled,
            },
        }
        print(json.dumps(output, indent=2))
        return 0

    print("=" * 60)
    print(f" Vulnora AI Diagnostic Status (v{vulnora.__version__})")
    print("=" * 60)
    print(f" Target Directory : {target_dir}")
    print(f" Git Installed    : {'Yes' if is_installed else 'No'}")
    print(f" Git Repository   : {'Yes' if repo_status.is_git else 'No'}")

    if repo_status.is_git:
        print(f" Repository Root  : {repo_status.root_path}")
        print(f" Current Branch   : {repo_status.current_branch or 'N/A'}")
        print(f" Head Commit      : {repo_status.current_commit or 'N/A'}")
        print(f" Working Tree     : {'Dirty (Uncommitted Changes)' if repo_status.is_dirty else 'Clean'}")
        prot_str = "YES (Protected)" if repo_status.is_current_branch_protected else "No"
        print(f" Protected Branch : {prot_str}")
        print(f" Hooks Directory  : {repo_status.hooks_dir}")
        print(f" Pre-push Hook    : {'Installed' if repo_status.hook_installed else 'Not installed'}")

    print(f" Primary Language : {lang_info.primary_language}")
    if lang_info.detected_languages:
        print(f" Detected Langs   : {', '.join(lang_info.detected_languages)}")
    if lang_info.manifest_files:
        print(f" Manifests Found  : {', '.join(lang_info.manifest_files)}")

    print("-" * 60)
    cfg_file = get_config_path(target_dir)
    print(f" Config File      : {cfg_file} ({'Found' if cfg_file.exists() else 'Default in-memory'})")
    print(f" Protected Branches: {', '.join(config.git.protected_branches)}")
    print(f" Enabled Scanners : {', '.join(config.scanners.enabled)}")
    print("=" * 60)

    return 0


def handle_scan(args: argparse.Namespace) -> int:
    """Handles `vulnora scan` command."""
    target_dir = Path(args.repo_dir).resolve() if args.repo_dir else Path.cwd().resolve()
    config = load_config(base_path=target_dir)
    engine = GitEngine(repo_path=target_dir)

    is_full = bool(args.full)
    changed_files: List[Path] = []

    # If diff-scoped, compute changed files in repository
    if not is_full:
        if engine.is_git_repository():
            changed_files = engine.get_diff_scoped_files()
            if not changed_files and not args.target_url:
                if getattr(args, "json", False):
                    empty_out = {
                        "target_path": str(target_dir),
                        "is_full_scan": False,
                        "total_findings": 0,
                        "scanner_results": [],
                        "findings": [],
                        "message": "No modified or staged files found for diff-scoped scan.",
                    }
                    print(json.dumps(empty_out, indent=2))
                else:
                    print("=" * 60)
                    print(" Vulnora AI Security Scan (Diff-Scoped)")
                    print("=" * 60)
                    print(f" Target Directory : {target_dir}")
                    print("[*] Working tree is clean. No changed or staged files detected.")
                    print("    Use 'vulnora scan --full' to inspect the entire repository.")
                    print("=" * 60)
                return 0
        else:
            # Not a git repo; automatically fallback to full scan
            is_full = True

    # Parse requested scanners
    requested: Optional[List[str]] = None
    if args.scanners:
        requested = [s.strip() for s in args.scanners.split(",") if s.strip()]

    orchestrator = ScannerOrchestrator(config=config)
    result = orchestrator.run_scanners(
        target_path=target_dir,
        is_full_scan=is_full,
        changed_files=changed_files,
        target_url=args.target_url,
        requested_scanners=requested,
        timeout_seconds=args.timeout,
    )

    if getattr(args, "json", False):
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print("=" * 70)
        mode_str = "Full Repository" if result.is_full_scan else f"Diff-Scoped ({len(changed_files)} files)"
        print(f" Vulnora AI Security Scan — {mode_str}")
        print("=" * 70)
        print(f" Target Path       : {result.target_path}")
        if result.target_url:
            print(f" Target DAST URL   : {result.target_url}")
        print(f" Duration          : {result.duration_seconds:.2f}s")
        print("-" * 70)
        print(" Scanner Executions:")
        for sr in result.scanner_results:
            status_icon = "[✔]" if sr.status == "COMPLETED" else ("[-]" if sr.status == "SKIPPED" else "[!]")
            extra_msg = f" — {sr.error_message}" if sr.error_message else ""
            print(f"   {status_icon} {sr.scanner_name.ljust(12)}: {sr.status.ljust(13)} ({sr.duration_seconds:.2f}s, {len(sr.findings)} findings){extra_msg}")

        print("-" * 70)
        print(f" Total Findings    : {result.total_findings}")
        print(f" Severity Breakdown: CRITICAL: {len(result.critical_findings)} | HIGH: {len(result.high_findings)} | MEDIUM: {len(result.medium_findings)} | LOW: {len(result.low_findings)} | INFO: {len(result.info_findings)}")
        print("=" * 70)

        if result.findings:
            print("\nFindings Detail:")
            for idx, f in enumerate(result.findings, 1):
                loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
                print(f"\n[{idx}] [{f.severity.value}] {f.title}")
                print(f"    Location   : {loc}")
                print(f"    Scanner    : {f.scanner_name} (Rule: {f.rule_id})")
                if f.snippet:
                    print(f"    Code/Match : {f.snippet.strip()}")
                if f.remediation:
                    print(f"    Remediation: {f.remediation}")
                if f.reference_urls:
                    print(f"    References : {', '.join(f.reference_urls[:2])}")
            print("\n" + "=" * 70)

    # Determine exit blocking behavior
    should_block = bool(args.block)
    if should_block and result.has_critical_or_high:
        return 1
    return 0


def handle_immune(args: argparse.Namespace) -> int:
    """Handles `vulnora immune` subcommands."""
    target_dir = Path(args.repo_dir).resolve() if args.repo_dir else Path.cwd().resolve()
    memory_file = get_vulnora_dir(target_dir) / "memory.json"
    store = ImmuneMemoryStore(memory_path=memory_file)

    if not getattr(args, "immune_command", None) or args.immune_command == "stats":
        metrics = store.get_metrics()
        if getattr(args, "json", False):
            print(json.dumps(metrics.to_dict(), indent=2))
            return 0
        print("=" * 60)
        print(" Vulnora AI AST Immune Memory Stats")
        print("=" * 60)
        print(f" Memory Path        : {memory_file}")
        print(f" Total Antibodies   : {metrics.total_records}")
        print("-" * 60)
        print(f" Records by Language: {json.dumps(metrics.records_by_language)}")
        print(f" Records by Action  : {json.dumps(metrics.records_by_resolution)}")
        print(f" Records by Severity: {json.dumps(metrics.records_by_severity)}")
        print("-" * 60)
        print(f" Tier 1 Exact Hits  : {metrics.tier1_hits}")
        print(f" Tier 2 Variant Hits: {metrics.tier2_hits}")
        print(f" Tier 3 Partial Hits: {metrics.tier3_hits}")
        print(f" Misses             : {metrics.misses}")
        print("=" * 60)
        return 0

    if args.immune_command == "export":
        out_path = args.output or (get_vulnora_dir(target_dir) / "antibody_pack.json")
        rules = [r.strip() for r in args.rules.split(",") if r.strip()] if getattr(args, "rules", None) else None
        try:
            exported = AntibodyPackManager.export_pack(
                store=store,
                output_path=out_path,
                pack_name=getattr(args, "name", "vulnora-antibodies"),
                selected_rule_ids=rules,
            )
            print(f"[✔] Successfully exported antibody pack: {exported}")
            return 0
        except Exception as exc:
            print(f"[-] Error exporting antibody pack: {exc}", file=sys.stderr)
            return 1

    if args.immune_command == "import":
        try:
            count = AntibodyPackManager.import_pack(
                pack_path=args.file,
                store=store,
                overwrite=getattr(args, "overwrite", False),
            )
            print(f"[✔] Successfully imported {count} antibodies into local immune memory.")
            return 0
        except Exception as exc:
            print(f"[-] Error importing antibody pack: {exc}", file=sys.stderr)
            return 1

    if args.immune_command == "inspect":
        records = store.get_all_records()
        if getattr(args, "rule_id", None):
            records = [r for r in records if r.rule_id.lower() == args.rule_id.lower()]

        if getattr(args, "json", False):
            print(json.dumps([r.to_dict() for r in records], indent=2))
            return 0

        print("=" * 70)
        print(f" Vulnora AI Stored Antibodies ({len(records)} records)")
        print("=" * 70)
        if not records:
            print("[*] No antibodies stored yet.")
        for idx, r in enumerate(records, 1):
            print(f"\n[{idx}] {r.id}")
            print(f"    Rule ID     : {r.rule_id} ({r.scanner_name})")
            print(f"    Language    : {r.language}")
            print(f"    Severity    : {r.severity.value}")
            print(f"    Resolution  : {r.resolution}")
            print(f"    AST Hash    : {r.exact_hash[:16]}...")
            if r.agents_rule:
                print(f"    Agent Rule  : {r.agents_rule}")
            if r.anonymized_template:
                print(f"    Template    : {r.anonymized_template[:80]}...")
        print("\n" + "=" * 70)
        return 0

    return 0


def handle_prompt(args: argparse.Namespace) -> int:
    """Handles `vulnora prompt` command."""
    target_dir = Path(args.repo_dir).resolve() if args.repo_dir else Path.cwd().resolve()
    memory_file = get_vulnora_dir(target_dir) / "memory.json"
    immune_store = ImmuneMemoryStore(memory_path=memory_file) if memory_file.exists() else None

    severity_val = Severity.from_string(args.severity)
    finding_title = args.title or f"Vulnerability detected in {args.file} ({args.rule})"

    finding = Finding(
        rule_id=args.rule,
        scanner_name=args.scanner,
        severity=severity_val,
        title=finding_title,
        description=f"Security issue {args.rule} identified by {args.scanner}.",
        file_path=args.file,
        line_number=args.line,
        remediation="Apply surgical remediation as per language security standards.",
    )

    compiler = SurgicalPromptCompiler(
        target_root=target_dir,
        immune_store=immune_store,
    )
    prompt = compiler.compile(finding)

    if getattr(args, "output", None):
        out_file = Path(args.output).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(prompt.compiled_markdown, encoding="utf-8")
        print(f"[✔] Compiled prompt saved to: {out_file}")

    if getattr(args, "json", False):
        print(json.dumps(prompt.to_dict(), indent=2))
        return 0

    if not getattr(args, "output", None):
        print(prompt.compiled_markdown)

    return 0


def handle_fix(args: argparse.Namespace) -> int:
    """Handles `vulnora fix` command."""
    target_dir = Path(args.repo_dir).resolve() if args.repo_dir else Path.cwd().resolve()
    config = load_config(base_path=target_dir)
    memory_file = get_vulnora_dir(target_dir) / "memory.json"
    immune_store = ImmuneMemoryStore(memory_path=memory_file)

    severity_val = Severity.from_string(args.severity)
    finding = Finding(
        rule_id=args.rule,
        scanner_name=args.scanner,
        severity=severity_val,
        title=f"Vulnerability {args.rule} in {args.file}",
        description=f"Security issue {args.rule} identified by {args.scanner}.",
        file_path=args.file,
        line_number=args.line,
        remediation="Apply surgical remediation as per language security standards.",
    )

    # Step 1: Compile surgical prompt
    compiler = SurgicalPromptCompiler(target_root=target_dir, immune_store=immune_store)
    prompt = compiler.compile(finding)

    # Step 2: Request remediation proposal from Cloud AI
    provider = args.provider or os.getenv("VULNORA_AI_PROVIDER") or config.ai.provider or "auto"
    model = args.model or os.getenv("VULNORA_AI_MODEL") or None
    api_key = args.api_key or None
    ai_timeout = getattr(args, "timeout", None) or getattr(config.ai, "timeout_seconds", None) or 60

    client = CloudAIClient(
        provider=provider,
        model=model,
        api_key=api_key,
        timeout_seconds=ai_timeout,
    )

    try:
        proposal = client.generate_remediation(prompt, dry_run=args.dry_run)
    except Exception as exc:
        if getattr(args, "json", False):
            print(json.dumps({"error": str(exc), "status": "FAILED"}))
        else:
            print(f"[-] Cloud AI remediation failed: {exc}", file=sys.stderr)
        return 1

    if args.no_verify:
        if getattr(args, "json", False):
            print(json.dumps(proposal.to_dict(), indent=2))
        else:
            print("=" * 65)
            print(f" Vulnora AI Remediation Proposal ({args.rule})")
            print("=" * 65)
            prov_str = f"{proposal.provider} ({proposal.model})" if proposal.provider else "Cloud AI"
            print(f" Provider     : {prov_str}")
            print(f" Root Cause   : {proposal.root_cause}")
            print(f" Explanation  : {proposal.explanation}")
            print(f" Prevent Rule : {proposal.agents_rule}")
            print("-" * 65)
            print(" Replacement Code:")
            print(proposal.replacement_code)
            print("=" * 65)
        return 0

    # Step 3: Run Fix Verification & Learning Loop
    verifier = FixVerifier(target_root=target_dir, config=config, immune_store=immune_store)
    result = verifier.verify_and_learn(finding=finding, proposal=proposal, auto_rollback=True)

    if getattr(args, "json", False):
        combined = {
            "proposal": proposal.to_dict(),
            "verification": result.to_dict(),
        }
        print(json.dumps(combined, indent=2))
        return 0 if result.success else 1

    print("=" * 65)
    status_str = "[✔] VERIFIED CLEAN" if result.success else "[!] VERIFICATION FAILED (ROLLED BACK)"
    print(f" Vulnora AI Fix & Verify — {status_str}")
    print("=" * 65)
    print(f" Target File       : {args.file}")
    print(f" Rule / Scanner    : {args.rule} ({args.scanner})")
    prov_str = f"{proposal.provider} ({proposal.model})" if proposal.provider else "Cloud AI"
    print(f" Provider          : {prov_str}")
    print(f" Root Cause        : {proposal.root_cause}")
    print(f" Explanation       : {proposal.explanation}")
    print(f" Duration          : {result.duration_seconds:.2f}s")
    print("-" * 65)
    if result.success:
        print(f" [✔] Antibody ID   : {result.antibody_id}")
        print(f" [✔] AGENTS.md Rule: {proposal.agents_rule}")
        if result.diff_unified:
            print("\nVerified Patch Diff:")
            print(result.diff_unified.strip())
    else:
        print(f" [!] Error Message : {result.message}")
        print(f" [!] Remaining     : {result.remaining_findings_count} finding(s) still flagged.")
    print("=" * 65)

    return 0 if result.success else 1


def handle_verify(args: argparse.Namespace) -> int:
    """Handles `vulnora verify` command."""
    target_dir = Path(args.repo_dir).resolve() if args.repo_dir else Path.cwd().resolve()
    config = load_config(base_path=target_dir)
    memory_file = get_vulnora_dir(target_dir) / "memory.json"
    immune_store = ImmuneMemoryStore(memory_path=memory_file)

    finding = Finding(
        rule_id=args.rule,
        scanner_name=args.scanner,
        severity=Severity.HIGH,
        title=f"Verification of {args.rule}",
        description=f"Rule {args.rule} in {args.file}",
        file_path=args.file,
    )

    rule_text = args.rule_text or f"Avoid code patterns matching {args.rule}."
    dummy_proposal = RemediationProposal(
        finding_id=finding.compute_fingerprint(),
        rule_id=args.rule,
        file_path=args.file,
        root_cause="Manual patch verification",
        explanation="Manual patch verification",
        replacement_code="",
        original_code="",
        agents_rule=rule_text,
    )

    verifier = FixVerifier(target_root=target_dir, config=config, immune_store=immune_store)
    result = verifier.verify_and_learn(finding=finding, proposal=dummy_proposal, auto_rollback=False)

    if getattr(args, "json", False):
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.success else 1

    print("=" * 65)
    status_str = "[✔] VERIFIED CLEAN" if result.success else "[!] VERIFICATION FAILED"
    print(f" Vulnora AI Patch Verification — {status_str}")
    print("=" * 65)
    print(f" Target File    : {args.file}")
    print(f" Scanner / Rule : {args.scanner} ({args.rule})")
    print(f" Result Message : {result.message}")
    if result.success and result.antibody_id:
        print(f" [✔] Antibody ID: {result.antibody_id}")
    print("=" * 65)

    return 0 if result.success else 1


def handle_mcp(args: argparse.Namespace) -> int:
    """Handles `vulnora mcp` command."""
    target_dir = Path(args.repo_dir).resolve() if args.repo_dir else Path.cwd().resolve()
    server = VulnoraMCPServer(repo_root=target_dir)
    server.serve_stdio()
    return 0


def handle_guard(args: argparse.Namespace) -> int:
    """
    Handles `vulnora guard` command:
    Autonomous Git pre-push guard with interactive TUI or headless CI blocking.
    """
    target_dir = Path(args.repo_dir).resolve() if args.repo_dir else Path.cwd().resolve()
    engine = GitEngine(repo_path=target_dir)
    config = load_config(base_path=target_dir)

    is_hook = getattr(args, "hook", False)
    protected_branch = None
    is_protected = True

    # If invoked from Git pre-push hook, read push refs from stdin if available
    if is_hook and not sys.stdin.isatty():
        try:
            raw_input = sys.stdin.read()
            push_refs = engine.parse_push_refs(raw_input)
            if push_refs:
                for ref in push_refs:
                    if ref.is_branch and ref.branch_name:
                        protected_branch = ref.branch_name
                        if engine.is_protected_branch(ref.branch_name, config.git.protected_branches):
                            is_protected = True
                            break
                        else:
                            is_protected = False
        except Exception:
            pass

    # If push target is explicitly an unprotected branch and full scan not requested
    if not is_protected and not getattr(args, "full", False):
        print("[*] Vulnora Guard: Target branch is not protected. Push permitted.")
        return 0

    # Determine interactive TTY vs headless CI
    force_no_tui = getattr(args, "no_tui", False) or os.getenv("VULNORA_NO_TUI", "").lower() in ("1", "true", "yes")
    is_interactive = False
    tty_stdin = None

    if not force_no_tui:
        if sys.stdin.isatty():
            is_interactive = True
        else:
            # During git push hook, stdin was piped with refs, but /dev/tty may be openable
            try:
                tty_stdin = open("/dev/tty", "r")
                is_interactive = True
            except Exception:
                is_interactive = False

    if is_interactive:
        prev_stdin = sys.stdin
        if tty_stdin:
            sys.stdin = tty_stdin
        try:
            from vulnora.tui import launch_tui
            return launch_tui(
                target_dir=target_dir,
                is_guard_mode=True,
                protected_branch=protected_branch or "main",
                config=config,
            )
        finally:
            if tty_stdin:
                try:
                    tty_stdin.close()
                except Exception:
                    pass
            sys.stdin = prev_stdin

    # Non-interactive / Headless CI Execution
    print(f"[*] Vulnora Guard (Headless CI Mode): Inspecting {target_dir.name}...")
    orchestrator = ScannerOrchestrator(config=config)
    res = orchestrator.run_scanners(
        target_path=target_dir,
        is_full_scan=getattr(args, "full", False),
        target_url=getattr(args, "target_url", None),
    )

    if res.has_critical_or_high:
        crit_count = len(res.critical_findings)
        high_count = len(res.high_findings)
        print("=" * 65, file=sys.stderr)
        print(f" [!] Vulnora Push Blocked: {crit_count} Critical, {high_count} High finding(s) detected!", file=sys.stderr)
        for f in res.critical_findings + res.high_findings:
            loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
            print(f"     - [{f.severity.value}] {f.rule_id} in {loc} ({f.scanner_name})", file=sys.stderr)
        print("=" * 65, file=sys.stderr)
        return 1

    print(f"[✔] Vulnora Guard: Clean! Zero blocking vulnerabilities detected across {len(res.findings)} finding(s).")
    return 0


def handle_pack(args: argparse.Namespace) -> int:
    """Handles `vulnora pack` command (alias for antibody pack operations)."""
    args.immune_command = getattr(args, "pack_command", None)
    return handle_immune(args)


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point for Vulnora."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        # If interactive TTY, launch TUI by default
        force_no_tui = os.getenv("VULNORA_NO_TUI", "").lower() in ("1", "true", "yes")
        if sys.stdin.isatty() and not force_no_tui:
            try:
                from vulnora.tui import launch_tui
                target_dir = Path(args.repo_dir).resolve() if args.repo_dir else Path.cwd().resolve()
                return launch_tui(target_dir=target_dir)
            except Exception as exc:
                print(f"[-] Error launching TUI: {exc}", file=sys.stderr)
                return 1
        parser.print_help()
        return 0

    if args.command == "init":
        return handle_init(args)
    elif args.command in ("status", "check-git"):
        return handle_status(args)
    elif args.command == "scan":
        return handle_scan(args)
    elif args.command == "immune":
        return handle_immune(args)
    elif args.command == "pack":
        return handle_pack(args)
    elif args.command == "guard":
        return handle_guard(args)
    elif args.command == "hook":
        args.hook = True
        return handle_guard(args)
    elif args.command == "tui":
        from vulnora.tui import launch_tui
        target_dir = Path(args.repo_dir).resolve() if args.repo_dir else Path.cwd().resolve()
        return launch_tui(target_dir=target_dir)
    elif args.command == "prompt":
        return handle_prompt(args)
    elif args.command == "fix":
        return handle_fix(args)
    elif args.command == "verify":
        return handle_verify(args)
    elif args.command == "mcp":
        return handle_mcp(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
