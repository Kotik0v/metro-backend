from .models import Station, FlowAnalysis, FlowAnalysisStation
from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate

# Сериализатор для добавления изображения к станции

class AddImageSerializer(serializers.Serializer):
    picture_url = serializers.URLField(required=True)



# Сериализатор для станции метро
class StationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Station
        fields = "__all__"

# Сериализатор для добавления станции в анализ потока
class AddStationToFlowAnalysisSerializer(serializers.Serializer):
    station_id = serializers.IntegerField(required=True)
    order = serializers.IntegerField(required=False)

    def validate(self, data):
        station_id = data.get('station_id')
        if not Station.objects.filter(id=station_id).exists():
            raise serializers.ValidationError("station_id is incorrect")
        return data

# Сериализатор для детальной информации о станции
class StationDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Station
        fields = ["pk", "title", "description", "status", "picture_url", "line_number", "line_name", "line_color", "average_visits"]

# Сериализатор для списка станций
class StationListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Station
        fields = ["pk", "title", "description", "status", "picture_url"]

# Сериализатор для информации о станции в анализе потока
class FlowAnalysisStationSerializer(serializers.ModelSerializer):
    station = StationSerializer(read_only=True)

    class Meta:
        model = FlowAnalysisStation
        fields = ['order', 'station']

# Сериализатор для анализа потока
class FlowAnalysisSerializer(serializers.ModelSerializer):
    stations = FlowAnalysisStationSerializer(many=True, read_only=True)
    user = serializers.StringRelatedField()
    moderator = serializers.StringRelatedField()

    class Meta:
        model = FlowAnalysis
        fields = ["id", "user", "moderator", "created_at", "formed_at", "ended_at", "status", "day_time", "flow", "stations"]

# Сериализатор для изменения анализа потока
class PutFlowAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = FlowAnalysis
        fields = ["status", "day_time", "flow"]

# Сериализаторы для аутентификации и работы с пользователями

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password')

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name')

    def validate_username(self, value):
        """
        Проверяем уникальность имени пользователя, только если оно изменяется.
        """
        user = self.instance
        if User.objects.filter(username=value).exclude(pk=user.pk).exists():
            raise serializers.ValidationError("A user with that username already exists.")
        return value

class AuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(username=data['username'], password=data['password'])
        if user is None:
            raise serializers.ValidationError("Неверные учетные данные")
        return {'user': user}

class CheckUsernameSerializer(serializers.Serializer):
    username = serializers.CharField()

    def validate(self, data):
        if not User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError("Пользователь не существует")
        return data

class AcceptFlowAnalysisSerializer(serializers.Serializer):
    accept = serializers.BooleanField()