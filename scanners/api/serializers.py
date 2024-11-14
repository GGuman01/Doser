from rest_framework import serializers


class DomainSerializer(serializers.Serializer):

    url = serializers.URLField()
