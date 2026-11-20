from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient


class ScansApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_scans_module_index(self):
        url = reverse("scans:index")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["module"], "scans")
        self.assertIn("integrated_scanners", response.data)

