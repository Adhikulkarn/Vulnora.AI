from rest_framework import serializers


class ProjectModuleInfoSerializer(serializers.Serializer):
    module = serializers.CharField()
    description = serializers.CharField()
    status = serializers.CharField()
    supported_features = serializers.ListField(child=serializers.CharField())

