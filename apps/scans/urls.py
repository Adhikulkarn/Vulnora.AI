from django.urls import path
from .views import ScansModuleIndexView

app_name = "scans"

urlpatterns = [
    path("", ScansModuleIndexView.as_view(), name="index"),
]

