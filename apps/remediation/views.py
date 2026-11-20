from rest_framework.views import APIView
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from .serializers import RemediationModuleInfoSerializer


class RemediationModuleIndexView(APIView):
    """
    Overview of Remediation and Issue Memory endpoints.
    """

    @extend_schema(summary="Remediation Module Overview", responses={200: RemediationModuleInfoSerializer})
    def get(self, request, *args, **kwargs):
        return Response(
            {
                "module": "remediation",
                "description": "Local and cloud-synced issue memory, root-cause tracking, and patch verification.",
                "status": "scaffolded",
                "supported_workflows": [
                    "Local Memory Sync (.vulnora/memory.json)",
                    "Rule-Based Instant Patching",
                    "Accept / Discard Interactive Workflow",
                    "Post-Fix Verification Rescans",
                ],
            }
        )

