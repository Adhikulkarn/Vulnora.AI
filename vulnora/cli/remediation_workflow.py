"""
Remediation workflow coordinator for Vulnora AI.
Orchestrates:
1. Memory lookup (.vulnora/memory.json) for previously verified fixes.
2. Remote AI inference fallback (via Ollama) when memory misses.
3. Interactive Accept/Discard patch loop respecting write_permission ('auto' vs 'prompt').
4. Automated patch application to target file.
5. Verification rescan to confirm resolution.
6. Local memory persistence of verified fixes and discarded findings.
"""

from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

from .ai_client import apply_patch_to_file, request_remediation, verify_scanner_fix
from .config import get_ai_config, get_write_permission, load_config
from .memory import (
    is_vulnerability_discarded,
    load_memory,
    lookup_memory_fix,
    record_discarded_finding,
    record_verified_fix,
    save_memory,
)
from .ui import (
    console,
    display_remediation_card,
    print_error,
    print_info,
    print_success,
    print_warning,
)


def run_remediation_workflow(
    project_root: Path,
    findings: List[Any],
    interactive: bool = True,
    auto_accept: Optional[bool] = None,
) -> Tuple[List[Any], List[Any], List[Any]]:
    """
    Executes the Accept/Discard remediation loop for detected findings.

    Args:
        project_root: Root directory of the repository/project.
        findings: List of NormalizedFinding objects or finding dictionaries.
        interactive: Whether interactive console prompts are permitted.
        auto_accept: If explicitly True/False, overrides config write_permission.

    Returns:
        Tuple of (resolved_findings, discarded_findings, unaddressed_findings)
    """
    resolved_findings: List[Any] = []
    discarded_findings: List[Any] = []
    unaddressed_findings: List[Any] = []

    if not findings:
        return resolved_findings, discarded_findings, unaddressed_findings

    memory_data = load_memory(project_root)
    ai_config = get_ai_config(project_root)
    configured_permission = get_write_permission(project_root)

    # Determine auto mode
    if auto_accept is True or configured_permission == "auto":
        is_auto_mode = True
    else:
        is_auto_mode = False

    can_prompt = interactive and sys.stdin.isatty() and not is_auto_mode

    for finding in findings:
        # Convert finding to dictionary representation
        if hasattr(finding, "to_dict"):
            f_dict = finding.to_dict()
        elif isinstance(finding, dict):
            f_dict = finding
        else:
            f_dict = {
                "title": getattr(finding, "title", "Security Finding"),
                "description": getattr(finding, "description", ""),
                "scanner_name": getattr(finding, "scanner_name", "unknown"),
                "rule_id": getattr(finding, "rule_id", "unknown"),
                "severity": getattr(finding, "severity", "MEDIUM"),
                "file_path": getattr(finding, "file_path", ""),
                "line_number": getattr(finding, "line_number", None),
                "end_line_number": getattr(finding, "end_line_number", None),
                "remediation": getattr(finding, "remediation", ""),
                "fingerprint": getattr(finding, "fingerprint", ""),
            }

        rule_id = f_dict.get("rule_id", "unknown")
        file_path_str = f_dict.get("file_path", "")

        # 1. Check if finding was previously discarded
        if is_vulnerability_discarded(memory_data, f_dict):
            console.print(
                f"[dim]• Finding [bold]{rule_id}[/bold] in [white]{file_path_str}[/white] "
                f"was previously marked as discarded. Bypassing prompt.[/dim]"
            )
            discarded_findings.append(finding)
            continue

        # 2. Check local issue memory first
        fix = lookup_memory_fix(memory_data, f_dict)
        source = "Local Issue Memory"

        # 3. If memory miss and AI is enabled, consult remote AI
        if not fix and ai_config.get("enabled", True):
            console.print(
                f"[cyan]ℹ Memory miss for [bold]{rule_id}[/bold]. "
                f"Consulting remote AI inference server ({ai_config.get('model', 'qwen2.5-coder:7b')})...[/cyan]"
            )
            fix = request_remediation(f_dict, project_root, ai_config)
            source = f"Remote Ollama ({ai_config.get('model', 'qwen2.5-coder:7b')})"

        # If no replacement code could be generated or found
        if not fix or not fix.get("replacement_code"):
            reason = fix.get("explanation") if fix else "No automated fix available"
            console.print(f"[yellow]▲ Could not obtain automated patch for {rule_id}: {reason}[/yellow]")
            unaddressed_findings.append(finding)
            continue

        # 4. Display remediation proposal card in Rich UI
        display_remediation_card(f_dict, fix, source=source)

        # 5. Determine decision
        if is_auto_mode:
            decision = "a"
            console.print("[dim]write_permission='auto' active. Auto-accepting patch...[/dim]")
        elif can_prompt:
            try:
                prompt_text = "[bold yellow]Apply this patch? [a]ccept / [d]iscard / [s]kip (default: a): [/bold yellow]"
                user_choice = console.input(prompt_text).strip().lower()
                decision = user_choice if user_choice else "a"
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Prompt interrupted. Skipping patch.[/dim]")
                decision = "s"
        else:
            # Non-interactive environment without auto-permission: do not hang
            console.print("[dim]Non-interactive environment with write_permission='prompt'. Skipping patch.[/dim]")
            decision = "s"

        # 6. Process decision
        if decision.startswith("a"):  # ACCEPT
            target_file = Path(file_path_str)
            if not target_file.is_absolute():
                target_file = (project_root / target_file).resolve()

            line_num = f_dict.get("line_number")
            end_line_num = f_dict.get("end_line_number")
            applied = apply_patch_to_file(target_file, line_num, fix["replacement_code"], end_line_num)

            if applied:
                print_info(f"Patch applied to {target_file.name}. Executing verification rescan...")
                verified = verify_scanner_fix(
                    project_root=project_root,
                    file_path=target_file,
                    scanner_name=f_dict.get("scanner_name", ""),
                    rule_id=rule_id,
                )

                if verified:
                    memory_data = record_verified_fix(
                        memory_data=memory_data,
                        finding=f_dict,
                        fix_payload=fix,
                        file_path=file_path_str,
                    )
                    save_memory(memory_data, project_root)
                    print_success(
                        f"Patch verified! Issue '{rule_id}' resolved and saved to .vulnora/memory.json."
                    )
                    resolved_findings.append(finding)
                else:
                    print_warning(
                        f"Verification rescan still detected '{rule_id}'. Patch kept for developer inspection."
                    )
                    unaddressed_findings.append(finding)
            else:
                print_error(f"Failed to apply patch to {target_file}.")
                unaddressed_findings.append(finding)

        elif decision.startswith("d"):  # DISCARD
            memory_data = record_discarded_finding(
                memory_data=memory_data,
                finding=f_dict,
                reason="discarded_by_developer",
            )
            save_memory(memory_data, project_root)
            print_info(f"Finding '{rule_id}' recorded in discarded_vulnerabilities.")
            discarded_findings.append(finding)

        else:  # SKIP
            unaddressed_findings.append(finding)

    return resolved_findings, discarded_findings, unaddressed_findings
