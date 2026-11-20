from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient


class RemediationApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_remediation_module_index(self):
        url = reverse("remediation:index")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["module"], "remediation")
        self.assertIn("supported_workflows", response.data)

