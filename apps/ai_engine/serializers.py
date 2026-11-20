from rest_framework import serializers


class AiEngineModuleInfoSerializer(serializers.Serializer):
    module = serializers.CharField()
    description = serializers.CharField()
    status = serializers.CharField()
    remote_endpoint = serializers.CharField()
    active_model = serializers.CharField()
    capabilities = serializers.ListField(child=serializers.CharField())

