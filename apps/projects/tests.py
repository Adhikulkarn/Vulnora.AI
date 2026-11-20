from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient


class ProjectsApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_projects_module_index(self):
        url = reverse("projects:index")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["module"], "projects")
        self.assertIn("supported_features", response.data)

