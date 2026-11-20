from django.urls import path
from .views import RemediationModuleIndexView

app_name = "remediation"

urlpatterns = [
    path("", RemediationModuleIndexView.as_view(), name="index"),
]

