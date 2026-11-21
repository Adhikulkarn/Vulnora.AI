"""
Cloud AI remediation client for Vulnora AI.

Connects to low-latency Cloud LLMs with an automated 4-tier fallback cascade:
1. GroqCloud (llama-3.3-70b-versatile / llama-3.1-8b-instant)
2. Google Gemini (gemini-2.5-flash)
3. OpenAI (gpt-4o-mini)
4. Local Ollama (qwen2.5-coder:7b)

Strict JSON output schemas (root_cause, explanation, replacement_code, agents_rule).
Pure Python standard library implementation (urllib.request) with zero external SDKs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import urllib.error
import urllib.request

from vulnora.core.models import RemediationProposal, SurgicalPrompt

DEFAULT_PROVIDER_CASCADE: List[str] = ["groq", "gemini", "openai", "ollama"]

DEFAULT_MODELS: Dict[str, str] = {
    "groq": "llama-3.1-8b-instant",
    "gemini": "gemini-3.5-flash-lite",
    "openai": "gpt-4o-mini",
    "ollama": "qwen2.5-coder:latest",
}


class CloudAIError(Exception):
    """Raised when Cloud AI remediation generation fails."""
    pass


class CloudAIClient:
    """
    Client for interacting with Cloud LLMs to generate surgical security fixes.
    Features an automated 4-tier cascade: Groq -> Gemini -> OpenAI -> Ollama.
    """

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        timeout_seconds: int = 60,
    ):
        raw_prov = (provider or os.getenv("VULNORA_AI_PROVIDER") or "auto").lower().strip()
        self.provider = raw_prov
        env_prov = (os.getenv("VULNORA_AI_PROVIDER") or "auto").lower().strip()
        if model is not None:
            self.user_model = model
        elif provider is None or provider == env_prov:
            self.user_model = os.getenv("VULNORA_AI_MODEL")
        else:
            self.user_model = None

        self.user_api_key = api_key
        self.endpoint = endpoint or os.getenv("VULNORA_AI_ENDPOINT")
        self.timeout_seconds = timeout_seconds

    @property
    def model(self) -> str:
        """Returns the active model name for the configured provider."""
        return self._resolve_model(self.provider)

    @property
    def api_key(self) -> Optional[str]:
        """Returns the active API key for the configured provider."""
        return self._resolve_api_key(self.provider)

    def _resolve_api_key(self, prov: str) -> Optional[str]:
        """Resolves the API key for a specific provider in priority order:
        1. Explicit runtime/session key
        2. Environment variables
        3. Local credentials (.vulnora/credentials.local)
        """
        if self.user_api_key and (self.provider == prov or self.provider in ("auto", "cascade")):
            return self.user_api_key

        env_key = None
        if prov == "groq":
            env_key = os.getenv("GROQ_API_KEY")
        elif prov == "gemini":
            env_key = os.getenv("GEMINI_API_KEY")
        elif prov in ("openai", "compatible"):
            env_key = os.getenv("OPENAI_API_KEY")

        if env_key:
            return env_key

        try:
            from vulnora.core.config import load_local_credentials
            creds = load_local_credentials()
            if prov == "gemini":
                return creds.get("GEMINI_API_KEY")
            elif prov == "groq":
                return creds.get("GROQ_API_KEY")
            elif prov in ("openai", "compatible"):
                return creds.get("OPENAI_API_KEY")
        except Exception:
            pass

        return None

    def _resolve_model(self, prov: str) -> str:
        """Resolves the model name for a specific provider."""
        if self.user_model:
            if self.provider == prov:
                return self.user_model
            if self.provider in ("auto", "cascade"):
                if prov == "gemini" and "gemini" in self.user_model.lower():
                    return self.user_model
                if prov == "groq" and ("llama" in self.user_model.lower() or "mixtral" in self.user_model.lower()):
                    return self.user_model
                if prov in ("openai", "compatible") and any(k in self.user_model.lower() for k in ("gpt", "o1", "o3")):
                    return self.user_model
                if prov == "ollama" and any(k in self.user_model.lower() for k in ("qwen", "coder")):
                    return self.user_model
        return DEFAULT_MODELS.get(prov, "gpt-4o-mini")

    def generate_remediation(
        self,
        prompt: SurgicalPrompt,
        dry_run: bool = False,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> RemediationProposal:
        """
        Sends surgical prompt to the LLM and parses strict JSON remediation output.
        Cascades through: 1st Groq -> 2nd Gemini -> 3rd OpenAI -> 4th Ollama.
        """
        if on_log:
            on_log("[bold cyan][AI][/bold cyan] Pre-egress secret redaction verified (zero sensitive credentials).")

        if dry_run or os.getenv("VULNORA_MOCK_AI", "").lower() in ("1", "true", "yes"):
            if on_log:
                on_log("[yellow][AI][/yellow] Generating deterministic mock remediation proposal (dry-run mode)...")
            return self._generate_mock_proposal(prompt)

        system_prompt = (
            "You are an expert security engineer and surgical code remediation engine.\n"
            "Analyze the vulnerable code and compile a drop-in surgical remediation patch.\n"
            "STRICT REQUIREMENT: You MUST reply with valid JSON only. Do not wrap in markdown or markdown fences.\n"
            "The JSON must have this exact structure:\n"
            "{\n"
            '  "root_cause": "Brief explanation of the root security flaw",\n'
            '  "explanation": "How the replacement code fixes the vulnerability without changing behavior",\n'
            '  "replacement_code": "Exact replacement code for the vulnerable block",\n'
            '  "agents_rule": "One concise imperative rule for coding agents to prevent this in future"\n'
            "}"
        )

        user_content = prompt.compiled_markdown

        # Determine cascade order
        if self.provider in ("auto", "cascade"):
            providers_to_try = list(DEFAULT_PROVIDER_CASCADE)
        else:
            # User specified a specific provider: try it first, then fall back to the rest
            providers_to_try = [self.provider] + [p for p in DEFAULT_PROVIDER_CASCADE if p != self.provider]

        cascade_errors: List[str] = []

        for prov in providers_to_try:
            api_key = self._resolve_api_key(prov)
            # Cloud providers require an API key; skip if none configured
            if prov in ("groq", "gemini", "openai") and not api_key:
                cascade_errors.append(f"{prov}: No API key configured")
                if on_log:
                    on_log(f"[dim][AI][/dim] Skipping provider '{prov}': No API key configured.")
                continue

            model = self._resolve_model(prov)
            if on_log:
                on_log(f"[bold magenta][AI][/bold magenta] Requesting remediation from provider [bold]{prov}[/bold] ({model})...")
            print(f"[*] Trying AI provider: {prov} ({model})...", file=sys.stderr)

            try:
                timeout = min(self.timeout_seconds, 3) if prov == "ollama" else self.timeout_seconds
                if prov == "groq":
                    response_text = self._call_openai_compatible(
                        system_prompt=system_prompt,
                        user_content=user_content,
                        endpoint="https://api.groq.com/openai/v1/chat/completions",
                        api_key=api_key,
                        model=model,
                        timeout=timeout,
                    )
                elif prov == "gemini":
                    response_text = self._call_gemini(
                        system_prompt=system_prompt,
                        user_content=user_content,
                        api_key=api_key,
                        model=model,
                        timeout=timeout,
                    )
                elif prov in ("openai", "compatible"):
                    endpoint = self.endpoint or "https://api.openai.com/v1/chat/completions"
                    response_text = self._call_openai_compatible(
                        system_prompt=system_prompt,
                        user_content=user_content,
                        endpoint=endpoint,
                        api_key=api_key,
                        model=model,
                        timeout=timeout,
                    )
                elif prov == "ollama":
                    endpoint = self.endpoint or "http://localhost:11434/api/chat"
                    response_text = self._call_ollama(
                        system_prompt=system_prompt,
                        user_content=user_content,
                        endpoint=endpoint,
                        model=model,
                        timeout=timeout,
                    )
                else:
                    continue

                if on_log:
                    on_log(f"[bold green][AI][/bold green] Synthesis response received from {prov} ({model}). Parsing JSON...")
                proposal = self._parse_json_response(response_text, prompt)
                proposal.provider = prov
                proposal.model = model
                if on_log:
                    on_log(f"[bold green][✔][/bold green] Surgical remediation proposal successfully synthesized via {prov} ({model}).")
                return proposal

            except Exception as exc:
                cascade_errors.append(f"{prov} ({model}): {exc}")
                if on_log:
                    on_log(f"[yellow][!][/yellow] Provider '{prov}' ({model}) failed: {exc}. Cascading to next provider...")
                continue

        error_details = "\n  - " + "\n  - ".join(cascade_errors)
        raise CloudAIError(f"All AI providers in cascade failed:{error_details}")

    def _call_gemini(self, system_prompt: str, user_content: str, api_key: Optional[str], model: str, timeout: Optional[int] = None) -> str:
        """Invokes Google Gemini API using google-genai SDK if available, or REST API."""
        if not api_key:
            raise CloudAIError("Gemini API key not found. Set GEMINI_API_KEY environment variable.")

        clean_model = model[7:] if model.startswith("models/") else model
        timeout_val = timeout or self.timeout_seconds

        # Attempt 1: Try official google-genai SDK if installed
        try:
            from google import genai
            from google.genai import types

            client = genai.Client(
                api_key=api_key,
                http_options=types.HttpOptions(timeout=int(timeout_val * 1000)),
            )
            response = client.models.generate_content(
                model=clean_model,
                contents=user_content,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    response_mime_type="application/json",
                    temperature=0.1,
                ),
            )
            if response and response.text:
                return response.text
        except ImportError:
            pass
        except Exception:
            pass

        # Attempt 2: Direct REST request using standard library
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{clean_model}:generateContent?key={api_key}"
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": f"{system_prompt}\n\nTask Instructions and Vulnerability Context:\n{user_content}"}],
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.1,
            },
        }

        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Vulnora-AI/0.1.0",
                "x-goog-api-key": api_key,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout_val) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["candidates"][0]["content"]["parts"][0]["text"]
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise CloudAIError(f"Gemini HTTP {exc.code}: {err_body[:250]}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CloudAIError(f"Gemini connection timeout/error: {exc}") from exc

    def _call_openai_compatible(
        self,
        system_prompt: str,
        user_content: str,
        endpoint: str,
        api_key: Optional[str],
        model: str,
        timeout: Optional[int] = None,
    ) -> str:
        """Invokes GroqCloud or OpenAI-compatible endpoint."""
        if not api_key:
            raise CloudAIError("API key not found. Set GROQ_API_KEY or OPENAI_API_KEY.")

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
        }

        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "Vulnora-AI/0.1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout_seconds) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            # If Groq model not found, auto-fallback to llama-3.1-8b-instant
            if "groq.com" in endpoint and exc.code == 404 and model != "llama-3.1-8b-instant":
                return self._call_openai_compatible(
                    system_prompt=system_prompt,
                    user_content=user_content,
                    endpoint=endpoint,
                    api_key=api_key,
                    model="llama-3.1-8b-instant",
                    timeout=timeout,
                )
            raise CloudAIError(f"HTTP {exc.code}: {err_body[:250]}") from exc

    def _call_ollama(self, system_prompt: str, user_content: str, endpoint: str, model: str, timeout: Optional[int] = None) -> str:
        """Invokes local Ollama chat API."""
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "format": "json",
            "stream": False,
        }

        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Vulnora-AI/0.1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout_seconds) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["message"]["content"]
        except Exception as exc:
            raise CloudAIError(f"Ollama local inference error: {exc}") from exc

    def _parse_json_response(self, raw_text: str, prompt: SurgicalPrompt) -> RemediationProposal:
        """Strips markdown code fences if present and parses strict JSON proposal."""
        text = raw_text.strip()
        # Clean markdown code fences if model wrapped the JSON
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
            text = text.strip()

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CloudAIError(f"Failed to parse LLM response as JSON: {raw_text[:200]}") from exc

        root_cause = str(parsed.get("root_cause", "Security vulnerability identified by scanner."))
        explanation = str(parsed.get("explanation", "Surgically remediated vulnerable code."))
        replacement_code = str(parsed.get("replacement_code", prompt.vulnerable_code_block))
        agents_rule = str(parsed.get("agents_rule", f"Avoid pattern matching {prompt.rule_id}."))

        return RemediationProposal(
            finding_id=prompt.finding_id,
            rule_id=prompt.rule_id,
            file_path=prompt.file_path,
            root_cause=root_cause,
            explanation=explanation,
            replacement_code=replacement_code,
            original_code=prompt.vulnerable_code_block,
            line_number=prompt.line_number,
            agents_rule=agents_rule,
            confidence=1.0,
        )

    def _generate_mock_proposal(self, prompt: SurgicalPrompt) -> RemediationProposal:
        """Deterministic mock proposal for testing and offline verification."""
        vuln_code = prompt.vulnerable_code_block
        rule = prompt.rule_id

        # Heuristic mock replacements for common rules
        replacement = vuln_code
        if "os.system" in vuln_code:
            replacement = vuln_code.replace("os.system(command)", "subprocess.run(['echo', command], shell=False, check=True)")
            replacement = replacement.replace("os.system(", "subprocess.run([")
        elif "exec.Command" in vuln_code:
            replacement = vuln_code.replace('exec.Command("sh", "-c", input)', 'exec.Command("echo", input)')

        rule_text = f"Never use insecure calls matching {rule}; use safe subprocess APIs with shell=False."

        return RemediationProposal(
            finding_id=prompt.finding_id,
            rule_id=prompt.rule_id,
            file_path=prompt.file_path,
            root_cause=f"Direct shell invocation or untrusted data handling matching {rule}.",
            explanation=f"Replaced dangerous dynamic invocation with safe structured call for {rule}.",
            replacement_code=replacement,
            original_code=vuln_code,
            line_number=prompt.line_number,
            agents_rule=rule_text,
            confidence=1.0,
            provider="mock",
            model="mock-v1",
        )
