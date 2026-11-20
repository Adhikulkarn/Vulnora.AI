from django.urls import path
from .views import ProjectModuleIndexView

app_name = "projects"

urlpatterns = [
    path("", ProjectModuleIndexView.as_view(), name="index"),
]

