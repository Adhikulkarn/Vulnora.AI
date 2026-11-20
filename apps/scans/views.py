from rest_framework.views import APIView
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from .serializers import ScansModuleInfoSerializer


class ScansModuleIndexView(APIView):
    """
    Overview of Security Scanner Orchestration endpoints.
    """

    @extend_schema(summary="Scans Module Overview", responses={200: ScansModuleInfoSerializer})
    def get(self, request, *args, **kwargs):
        return Response(
            {
                "module": "scans",
                "description": "Orchestrates and normalizes findings from Gitleaks, Semgrep, Bandit, and OSV-Scanner.",
                "status": "scaffolded",
                "integrated_scanners": [
                    "Gitleaks (Secrets detection)",
                    "Semgrep (SAST)",
                    "Bandit (Python security)",
                    "OSV-Scanner (Dependency vulnerabilities)",
                ],
            }
        )

