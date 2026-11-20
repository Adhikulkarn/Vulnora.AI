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
        return Response(
            {
                "module": "ai_engine",
                "description": "Gateway for routing complex vulnerabilities to dedicated remote AI inference (Ollama).",
                "status": "scaffolded",
                "remote_endpoint": getattr(settings, "VULNORA_REMOTE_AI_ENDPOINT", "http://127.0.0.1:11434"),
                "active_model": getattr(settings, "VULNORA_REMOTE_AI_MODEL", "qwen2.5-coder:7b"),
                "capabilities": [
                    "Sensitive Secret Redaction before egress",
                    "Surrounding AST Context Extraction",
                    "Remote Ollama / Open-Weight Reasoning (Qwen/Devstral)",
                    "Unified Patch & Explanation Generation",
                ],
            }
        )

