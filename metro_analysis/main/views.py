from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import login, logout, authenticate
from django.db.models import Max
from datetime import datetime
import numpy as np
from .models import Station, FlowAnalysis, FlowAnalysisStation
from .serializers import (
    StationSerializer,
    StationDetailSerializer,
    FlowAnalysisSerializer,
    FlowAnalysisStationSerializer,
    AddStationToFlowAnalysisSerializer,
    UserRegistrationSerializer,
    UserUpdateSerializer,
    AuthTokenSerializer,
    AcceptFlowAnalysisSerializer,
    AddImageSerializer
)
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from rest_framework.authentication import SessionAuthentication

class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return

class IsModerator(IsAuthenticated):
    def has_permission(self, request, view):
        return super().has_permission(request, view) and request.user.is_staff

# Станции метро (Услуги)
class StationListView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Получение списка станций метро и, если пользователь аутентифицирован, информации о его текущей заявке.",
        responses={200: StationSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        stations = Station.objects.filter(status=Station.ACTIVE)

        if 'title' in request.GET:
            stations = stations.filter(title__icontains=request.GET['title'])

        serializer = StationSerializer(stations, many=True)
        response_data = serializer.data

        if request.user and request.user.is_authenticated:
            flow_analysis = FlowAnalysis.objects.filter(user=request.user, status='draft').first()
            if flow_analysis:
                draft_request_id = flow_analysis.id
                count_stations = flow_analysis.stations.count()

                flow_analysis_stations = FlowAnalysisStation.objects.filter(flow_analysis=flow_analysis).order_by(
                    'order')
                flow_stations_serializer = FlowAnalysisStationSerializer(flow_analysis_stations, many=True)

                extra_data = {
                    'draft_request_id': draft_request_id,
                    'count_stations': count_stations,
                    'stations_in_draft': flow_stations_serializer.data
                }
            else:
                extra_data = {
                    'draft_request_id': None,
                    'count_stations': 0,
                    'stations_in_draft': []
                }

            response_data = {
                'stations': response_data,
                'draft_info': extra_data
            }

        return Response({'stations': response_data}, status=status.HTTP_200_OK)

class StationDetailView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Получение детальной информации о станции метро по ID.",
        responses={200: StationDetailSerializer()}
    )
    def get(self, request, pk, *args, **kwargs):
        station = get_object_or_404(Station, pk=pk)
        serializer = StationDetailSerializer(station)
        return Response(serializer.data, status=status.HTTP_200_OK)

class StationCreateView(APIView):
    permission_classes = [IsModerator]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Создание новой станции метро.",
        request_body=StationDetailSerializer,
        responses={201: StationDetailSerializer()}
    )
    def post(self, request, *args, **kwargs):
        serializer = StationDetailSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class StationUpdateView(APIView):
    permission_classes = [IsModerator]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Обновление информации о станции метро.",
        request_body=StationDetailSerializer,
        responses={200: StationDetailSerializer()}
    )
    def put(self, request, pk, *args, **kwargs):
        station = get_object_or_404(Station, pk=pk)
        serializer = StationDetailSerializer(station, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class StationDeleteView(APIView):
    permission_classes = [IsModerator]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Удаление станции метро по ID.",
        responses={204: "No Content"}
    )
    def delete(self, request, pk, *args, **kwargs):
        station =get_object_or_404(Station, pk=pk)
        station.status = Station.DELETED
        station.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

class StationImageView(APIView):
    permission_classes = [IsModerator]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Загрузка или обновление изображения станции метро.",
        request_body=AddImageSerializer,
        responses={200: "Image updated successfully"}
    )
    def post(self, request, pk, *args, **kwargs):
        station = get_object_or_404(Station, pk=pk)
        serializer = AddImageSerializer(data=request.data)

        if serializer.is_valid():
            station.picture_url = serializer.validated_data['picture_url']
            station.save()
            return Response({'message': 'Изображение станции обновлено'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Анализы потоков (Заявки)
class FlowAnalysisListView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Получение списка всех анализов потоков пассажиров.",
        responses={200: FlowAnalysisSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        if request.user.is_staff:
            flow_analyses = FlowAnalysis.objects.all()
        else:
            flow_analyses = FlowAnalysis.objects.filter(user=request.user).exclude(status=FlowAnalysis.DELETED)

        serializer = FlowAnalysisSerializer(flow_analyses, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class FlowAnalysisDetailView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Получение детальной информации об анализе потока по ID.",
        responses={200: FlowAnalysisSerializer()}
    )
    def get(self, request, pk, *args, **kwargs):
        flow_analysis = get_object_or_404(FlowAnalysis, pk=pk)

        if not request.user.is_staff and (flow_analysis.user != request.user or flow_analysis.status == FlowAnalysis.DELETED):
            return Response({'error': 'Вы не можете просматривать этот анализ потока'}, status=status.HTTP_403_FORBIDDEN)

        serializer = FlowAnalysisSerializer(flow_analysis)
        return Response(serializer.data, status=status.HTTP_200_OK)

class FlowAnalysisCreateView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Создание нового анализа потока пассажиров.",
        request_body=FlowAnalysisSerializer,
        responses={201: FlowAnalysisSerializer()}
    )
    def post(self, request, *args, **kwargs):
        serializer = FlowAnalysisSerializer(data={**request.data, 'user': request.user.id})
        if serializer.is_valid():
            flow_analysis = serializer.save()
            return Response(FlowAnalysisSerializer(flow_analysis).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FlowAnalysisUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Обновление анализа потока пассажиров по ID.",
        request_body=FlowAnalysisSerializer,
        responses={200: FlowAnalysisSerializer()}
    )
    def put(self, request, pk, *args, **kwargs):
        flow_analysis = get_object_or_404(FlowAnalysis, pk=pk)
        if flow_analysis.user != request.user and not request.user.is_staff:
            return Response({'error': 'Вы не можете редактировать этот анализ потока'}, status=status.HTTP_403_FORBIDDEN)
        serializer = FlowAnalysisSerializer(flow_analysis, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FlowAnalysisFormView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Формирование анализа потока пассажиров (перевод из статуса 'черновик' в 'сформирован').",
        responses={200: "Request successfully formed", 400: "Bad request"}
    )
    def put(self, request, pk, *args, **kwargs):
        flow_analysis = get_object_or_404(FlowAnalysis, pk=pk)

        if flow_analysis.user != request.user:
            return Response({'error': 'Вы не можете формировать этот анализ потока'}, status=status.HTTP_403_FORBIDDEN)

        if flow_analysis.status != FlowAnalysis.DRAFT:
            return Response({'error': 'Только черновик можно формировать'}, status=status.HTTP_400_BAD_REQUEST)

        flow_analysis.status = FlowAnalysis.FORMED
        flow_analysis.formed_at = datetime.now()
        flow_analysis.save()
        return Response(FlowAnalysisSerializer(flow_analysis).data, status=status.HTTP_200_OK)

class FlowAnalysisCompleteView(APIView):
    permission_classes = [IsModerator]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Завершение анализа потока пассажиров (перевод из 'сформирован' в 'завершён' или 'отклонён').",
        request_body=AcceptFlowAnalysisSerializer,
        responses={200: "Request moderated successfully", 400: "Bad request"}
    )
    def put(self, request, pk, *args, **kwargs):
        flow_analysis = get_object_or_404(FlowAnalysis, pk=pk)

        if flow_analysis.status != FlowAnalysis.FORMED:
            return Response({'error': 'Только сформированный анализ потока можно завершать'},
                            status=status.HTTP_400_BAD_REQUEST)

        serializer = AcceptFlowAnalysisSerializer(data=request.data)
        if serializer.is_valid():
            if serializer.validated_data['accept']:
                flow_analysis.status = FlowAnalysis.COMPLETED
                flow_analysis.ended_at = datetime.now()

                for station in flow_analysis.stations.all():
                    station.flow = calculate_poisson_flow(station.station.average_visits,
                                                          flow_analysis.day_time)
                    station.save()

                flow_analysis.moderator = request.user
            else:
                flow_analysis.status = FlowAnalysis.CANCELLED
                flow_analysis.ended_at = datetime.now()
                flow_analysis.moderатор = request.user
            flow_analysis.save()
            return Response(FlowAnalysisSerializer(flow_analysis).data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FlowAnalysisDeleteView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Удаление анализа потока по ID.",
        responses={204: "No Content"}
    )
    def delete(self, request, pk, *args, **kwargs):
        flow_analysis = get_object_or_404(FlowAnalysis, pk=pk)
        if flow_analysis.user != request.user and not request.user.is_staff:
            return Response({'error': 'Вы не можете удалять этот анализ потока'},
                            status=status.HTTP_403_FORBIDDEN)
        flow_analysis.status = FlowAnalysis.DELETED
        flow_analysis.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

class RemoveStationFromFlowAnalysisView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Удаление станции из анализа потока по ID станции и ID анализа.",
        responses={204: "No Content", 403: "Forbidden", 404: "Not Found"}
    )
    def delete(self, request, flow_analysis_id, station_id, *args, **kwargs):
        flow_analysis = get_object_or_404(FlowAnalysis, pk=flow_analysis_id)

        if flow_analysis.user != request.user and not request.user.is_staff:
            return Response({'error': 'Вы не можете редактировать этот анализ потока'},
                            status=status.HTTP_403_FORBIDDEN)

        FlowAnalysisStation.objects.filter(flow_analysis=flow_analysis, station_id=station_id).delete()
        return Response({'message': 'Станция удалена из анализа потока'}, status=status.HTTP_204_NO_CONTENT)

class UpdateStationInFlowAnalysisView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Обновление порядка станции в анализе потока.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'order': openapi.Schema(type=openapi.TYPE_INTEGER,
                                        description="Новый порядок станции в анализе")
            },
            required=['order']),
        responses={200: "Order updated successfully", 400: "Bad request", 404: "Not Found"}
    )
    def put(self, request, flow_analysis_id, station_id, *args, **kwargs):
        station_in_flow_analysis = get_object_or_404(FlowAnalysisStation, flow_analysis_id=flow_analysis_id, station_id=station_id)

        if station_in_flow_analysis.flow_analysis.user != request.user and not request.user.is_staff:
            return Response({'error': 'Вы не можете редактировать этот анализ потока'}, status=status.HTTP_403_FORBIDDEN)

        if 'order' in request.data:
            station_in_flow_analysis.order = request.data['order']
            station_in_flow_analysis.save()
            return Response({'message': 'Порядок станции в анализе потока обновлён'}, status=status.HTTP_200_OK)
        return Response({'error': 'Необходимо указать новый порядок станции'}, status=status.HTTP_400_BAD_REQUEST)

class AddStationToFlowAnalysisView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Добавление станции в анализ потока.",
        request_body=AddStationToFlowAnalysisSerializer,
        responses={200: "Station added to flow analysis", 400: "Bad request"}
    )
    def post(self, request, *args, **kwargs):
        flow_analysis = FlowAnalysis.objects.filter(user=request.user, status=FlowAnalysis.DRAFT).first()
        if not flow_analysis:
            flow_analysis = FlowAnalysis.objects.create(user=request.user, status=FlowAnalysis.DRAFT)

        serializer = AddStationToFlowAnalysisSerializer(data=request.data)
        if serializer.is_valid():
            station_id = serializer.validated_data['station_id']
            order = serializer.validated_data.get('order')

            if order is None:
                order = (FlowAnalysisStation.objects.filter(flow_analysis=flow_analysis).aggregate(Max('order'))['order__max'] or 0) + 1

            FlowAnalysisStation.objects.create(
                flow_analysis=flow_analysis,
                station_id=station_id,
                order=order,
                flow=None  # поле nullable
            )

            return Response({'message': 'Станция добавлена в анализ потока'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Пользователи
class UserRegistrationView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Регистрация нового пользователя.",
        request_body=UserRegistrationSerializer,
        responses={201: UserRegistrationSerializer(), 400: "Bad Request"}
    )
    def post(self, request, *args, **kwargs):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            login(request, user)  # Log in the user immediately after registration
            return Response({
                'message': 'Пользователь успешно зарегистрирован',
                'username': user.username,
                'email': user.email
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Обновление профиля пользователя.",
        request_body=UserUpdateSerializer,
        responses={200: UserUpdateSerializer(), 400: "Bad Request"}
    )
    def put(self, request, *args, **kwargs):
        serializer = UserUpdateSerializer(instance=request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Вход пользователя в систему.",
        request_body=AuthTokenSerializer,
        responses={200: "Login successful", 400: "Invalid credentials"}
    )
    def post(self, request, *args, **kwargs):
        serializer = AuthTokenSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            login(request, user)
            return Response({
                'message': 'Пользователь успешно вошёл в систему',
                'username': user.username
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Выход пользователя из системы.",
        responses={204: "Logout successful"}
    )
    def post(self, request, *args, **kwargs):
        logout(request)
        return Response({'message': 'Пользователь успешно вышел из системы'}, status=status.HTTP_204_NO_CONTENT)


def calculate_poisson_flow(average_visits, time_of_day):
    """
    Рассчитывает поток посетителей на основе среднего количества посещений и времени дня.
    """
    time_factor = {
        'morning': 0.6,
        'day': 1.0,
        'evening': 0.8,
        'night': 0.5
    }.get(time_of_day, 1.0)

    lambda_value = average_visits * time_factor
    return np.random.poisson(lam=lambda_value)