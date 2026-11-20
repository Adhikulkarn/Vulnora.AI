from django.urls import path
from .views import (
    ScanDetailView,
    ScanListCreateView,
    ScanSummaryView,
    ScansModuleIndexView,
    VulnerabilityListView,
)

app_name = "scans"

urlpatterns = [
    # Scans Endpoints
    path("", ScanListCreateView.as_view(), name="scan-list-create"),
    path("info/", ScansModuleIndexView.as_view(), name="index"),
    path("vulnerabilities/", VulnerabilityListView.as_view(), name="scans-vulnerabilities"),
    path("<uuid:pk>/", ScanDetailView.as_view(), name="scan-detail"),
    path("<uuid:pk>/summary/", ScanSummaryView.as_view(), name="scan-summary"),
]
