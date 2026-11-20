from django.urls import path
from .views import AiEngineModuleIndexView

app_name = "ai_engine"

urlpatterns = [
    path("", AiEngineModuleIndexView.as_view(), name="index"),
]

