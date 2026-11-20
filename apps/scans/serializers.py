from rest_framework import serializers


class ScansModuleInfoSerializer(serializers.Serializer):
    module = serializers.CharField()
    description = serializers.CharField()
    status = serializers.CharField()
    integrated_scanners = serializers.ListField(child=serializers.CharField())

