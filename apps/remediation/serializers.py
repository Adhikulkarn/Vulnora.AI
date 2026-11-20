from rest_framework import serializers


class RemediationModuleInfoSerializer(serializers.Serializer):
    module = serializers.CharField()
    description = serializers.CharField()
    status = serializers.CharField()
    supported_workflows = serializers.ListField(child=serializers.CharField())

