from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient


class AiEngineApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_ai_engine_module_index(self):
        url = reverse("ai_engine:index")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["module"], "ai_engine")
        self.assertIn("active_model", response.data)
        self.assertIn("capabilities", response.data)

