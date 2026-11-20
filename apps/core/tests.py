from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient


class CoreApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_health_check_endpoint(self):
        url = reverse("core:health-check")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "healthy")
        self.assertEqual(response.data["service"], "vulnora-backend")

    def test_system_status_endpoint(self):
        url = reverse("core:system-status")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "operational")
        self.assertEqual(response.data["database"]["status"], "healthy")

    def test_api_root_navigation(self):
        url = reverse("core:api-root")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("endpoints", response.data)
        self.assertIn("documentation", response.data)

    def test_swagger_schema_accessible(self):
        response = self.client.get("/api/schema/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_swagger_ui_accessible(self):
        response = self.client.get("/api/docs/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_redoc_ui_accessible(self):
        response = self.client.get("/api/redoc/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

