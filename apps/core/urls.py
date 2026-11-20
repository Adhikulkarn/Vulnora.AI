from django.urls import path
from .views import ApiRootView, HealthCheckView, SystemStatusView

app_name = "core"

urlpatterns = [
    path("", ApiRootView.as_view(), name="api-root"),
    path("health/", HealthCheckView.as_view(), name="health-check"),
    path("status/", SystemStatusView.as_view(), name="system-status"),
]

