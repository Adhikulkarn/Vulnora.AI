# Autonomous Agent Security Rules (Managed by Vulnora AI)
> DO NOT remove or bypass these rules. They prevent known security regressions detected and verified in this repository.

## Python Security Guardrails
- **[CUSTOM-SECURITY-RULE]**: Always parse command strings with `shlex.split()` before passing to `subprocess.run` with `shell=False` to ensure secure and correct argument handling.
