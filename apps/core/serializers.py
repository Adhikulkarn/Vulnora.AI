from rest_framework import serializers


class HealthCheckSerializer(serializers.Serializer):
    status = serializers.CharField()
    service = serializers.CharField()
    version = serializers.CharField()
    timestamp = serializers.DateTimeField()


class SystemStatusSerializer(serializers.Serializer):
    status = serializers.CharField()
    service = serializers.CharField()
    version = serializers.CharField()
    database = serializers.DictField()
    environment = serializers.DictField()
    vulnora_config = serializers.DictField()

