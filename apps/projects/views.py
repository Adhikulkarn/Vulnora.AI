from rest_framework.views import APIView
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from .serializers import ProjectModuleInfoSerializer


class ProjectModuleIndexView(APIView):
    """
    Overview of Projects and Policy Engine endpoints.
    """

    @extend_schema(summary="Projects Module Overview", responses={200: ProjectModuleInfoSerializer})
    def get(self, request, *args, **kwargs):
        return Response(
            {
                "module": "projects",
                "description": "Repository registration, branch protection policies, and CLI configuration management.",
                "status": "scaffolded",
                "supported_features": [
                    "Repository Profiles",
                    "Protected Branch Rules (main, production)",
                    "Write Permission Policies (prompt vs auto)",
                    "Deterministic Push Policy Gatekeeping",
                ],
            }
        )

