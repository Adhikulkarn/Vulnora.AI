import os
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from .serializers import AiEngineModuleInfoSerializer


class AiEngineModuleIndexView(APIView):
    """
    Overview of Remote AI Inference Gateway endpoints.
    """

    @extend_schema(summary="AI Engine Module Overview", responses={200: AiEngineModuleInfoSerializer})
    def get(self, request, *args, **kwargs):
        try:
            from vulnora.cli.config import load_config
            ai_cfg = load_config().get("ai", {})
        except Exception:
            ai_cfg = {}

        endpoint = os.getenv(
            "VULNORA_REMOTE_AI_ENDPOINT",
            ai_cfg.get("base_url") or getattr(settings, "VULNORA_REMOTE_AI_ENDPOINT", "http://127.0.0.1:11435"),
        )
        model = os.getenv(
            "VULNORA_REMOTE_AI_MODEL",
            ai_cfg.get("model") or getattr(settings, "VULNORA_REMOTE_AI_MODEL", "qwen2.5-coder:7b"),
        )
        think = ai_cfg.get("think", getattr(settings, "VULNORA_REMOTE_AI_THINK", False))

        return Response(
            {
                "module": "ai_engine",
                "description": "Gateway for routing complex vulnerabilities to dedicated remote AI inference (Ollama).",
                "status": "operational",
                "remote_endpoint": endpoint,
                "active_model": model,
                "think": think,
                "capabilities": [
                    "Sensitive Secret Redaction before egress",
                    "Surrounding AST Context Extraction",
                    "Remote Ollama / Open-Weight Reasoning (Qwen/Devstral)",
                    "Unified Patch & Explanation Generation",
                    "Local Issue Memory Lookup & Verification Rescan",
                ],
            }
        )

