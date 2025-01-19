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
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils import timezone

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
        print("StationListView - начало обработки запроса")
        print(f"Пользователь аутентифицирован: {request.user.is_authenticated}")
        
        # Получаем параметр поиска из запроса
        title = request.query_params.get('title', '')
        
        # Получаем и фильтруем станции
        stations = Station.objects.all()
        if title:
            stations = stations.filter(title__icontains=title)
        
        stations_data = StationSerializer(stations, many=True).data
        
        # Для авторизованного пользователя добавляем информацию о черновике
        if request.user and request.user.is_authenticated:
            print(f"Поиск черновика для пользователя: {request.user.username}")
            flow_analysis = FlowAnalysis.objects.filter(
                user=request.user, 
                status='draft'
            ).first()
            
            if flow_analysis:
                print(f"Найден черновик ID: {flow_analysis.id}")
                draft_request_id = flow_analysis.id
                count_stations = flow_analysis.stations.count()
                print(f"Количество станций в черновике: {count_stations}")

                flow_analysis_stations = FlowAnalysisStation.objects.filter(
                    flow_analysis=flow_analysis
                ).order_by('order')
                
                flow_stations_serializer = FlowAnalysisStationSerializer(
                    flow_analysis_stations, 
                    many=True
                )

                extra_data = {
                    'draft_request_id': draft_request_id,
                    'count_stations': count_stations,
                    'stations_in_draft': flow_stations_serializer.data
                }
            else:
                print("Черновик не найден")
                extra_data = {
                    'draft_request_id': None,
                    'count_stations': 0,
                    'stations_in_draft': []
                }

            return Response({
                'stations': stations_data,
                'draft_info': extra_data
            }, status=status.HTTP_200_OK)
        
        # Для неавторизованного пользователя возвращаем только список станций
        return Response(stations_data, status=status.HTTP_200_OK)

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
    def get(self, request):
        if request.user.is_staff:
            queryset = FlowAnalysis.objects.all()
        else:
            queryset = FlowAnalysis.objects.filter(
                user=request.user
            ).exclude(status=FlowAnalysis.DELETED)
        
        status = request.query_params.get('status')
        date_start = request.query_params.get('date_start')
        date_end = request.query_params.get('date_end')

        if status:
            if status != 'all' and status != '':  # Проверяем, что статус не пустой и не 'all'
                queryset = queryset.filter(status=status)
        
        if date_start:
            date_start = datetime.strptime(date_start, '%Y-%m-%d')
            date_start = timezone.make_aware(
                date_start.replace(hour=0, minute=0, second=0, microsecond=0)
            )
            queryset = queryset.filter(created_at__gte=date_start)
            
        if date_end:
            date_end = datetime.strptime(date_end, '%Y-%m-%d')
            date_end = timezone.make_aware(
                date_end.replace(hour=23, minute=59, second=59, microsecond=999999)
            )
            queryset = queryset.filter(created_at__lte=date_end)

        serializer = FlowAnalysisSerializer(queryset, many=True)
        return Response(serializer.data)

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
            flow_analysis.created_at = timezone.now()
            flow_analysis.save()
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
    def post(self, request, pk, *args, **kwargs):
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
        operation_description="Формирование анализа потока пассажиров по ID.",
        responses={200: FlowAnalysisSerializer()}
    )
    def post(self, request, pk, *args, **kwargs):
        flow_analysis = get_object_or_404(FlowAnalysis, pk=pk)
        if flow_analysis.user != request.user and not request.user.is_staff:
            return Response(
                {'error': 'Вы не можете формировать этот анализ потока'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        flow_analysis.status = FlowAnalysis.FORMED
        flow_analysis.formed_at = timezone.now()
        flow_analysis.save()
        return Response(status=status.HTTP_200_OK)

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
                flow_analysis.ended_at = timezone.now()

                for station in flow_analysis.stations.all():
                    station.flow = calculate_poisson_flow(station.station.average_visits,
                                                          flow_analysis.day_time)
                    station.save()

                flow_analysis.moderator = request.user
            else:
                flow_analysis.status = FlowAnalysis.CANCELLED
                flow_analysis.ended_at = timezone.now()
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
    def post(self, request, pk, *args, **kwargs):
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

    def post(self, request, *args, **kwargs):
        flow_analysis = FlowAnalysis.objects.filter(
            user=request.user, 
            status=FlowAnalysis.DRAFT
        ).first()

        if not flow_analysis:
            return Response(
                {'error': 'Черновик не найден'}, 
                status=status.HTTP_404_NOT_FOUND
            )

        station_id = request.data.get('station_id')
        if not station_id:
            return Response(
                {'error': 'Не указан ID станции'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        FlowAnalysisStation.objects.filter(
            flow_analysis=flow_analysis, 
            station_id=station_id
        ).delete()

        return Response(
            {'message': 'Станция удалена из анализа потока'}, 
            status=status.HTTP_200_OK
        )

@method_decorator(csrf_exempt, name='dispatch')
class UpdateStationInFlowAnalysisView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CsrfExemptSessionAuthentication]

    def post(self, request, flow_analysis_id, station_id, *args, **kwargs):
        print('11. Backend: Начало метода post')
        print('12. Backend: Параметры:', {
            'flow_analysis_id': flow_analysis_id,
            'station_id': station_id,
            'request.data': request.data,
            'user': request.user.username,
            'is_staff': request.user.is_staff
        })
        
        flow_analysis = get_object_or_404(FlowAnalysis, id=flow_analysis_id)
        
        if not request.user.is_staff and (flow_analysis.user != request.user or flow_analysis.status != FlowAnalysis.DRAFT):
            return Response(
                {'error': 'Недостаточно прав или неверный статус анализа'}, 
                status=status.HTTP_403_FORBIDDEN
            )

        station_in_flow_analysis = get_object_or_404(
            FlowAnalysisStation,
            flow_analysis=flow_analysis,
            station_id=station_id
        )

        if request.user.is_staff and 'flow' in request.data:
            station_in_flow_analysis.flow = request.data['flow']
            station_in_flow_analysis.save()
            return Response(status=status.HTTP_200_OK)
        elif not request.user.is_staff and 'order' in request.data:
            station_in_flow_analysis.order = request.data['order']
            station_in_flow_analysis.save()
            return Response(status=status.HTTP_200_OK)
            
        return Response(
            {'error': 'Необходимо указать корректные данные для обновления'},
            status=status.HTTP_400_BAD_REQUEST
        )

class AddStationToFlowAnalysisView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CsrfExemptSessionAuthentication]

    @swagger_auto_schema(
        operation_description="Добавление станции в анализ потока.",
        request_body=AddStationToFlowAnalysisSerializer,
        responses={200: "Station added to flow analysis", 400: "Bad request"}
    )
    def post(self, request, *args, **kwargs):
        # Проверяем существование черновика
        flow_analysis = FlowAnalysis.objects.filter(
            user=request.user, 
            status=FlowAnalysis.DRAFT
        ).first()

        # Если черновика нет, создаем новый
        if not flow_analysis:
            flow_analysis = FlowAnalysis.objects.create(
                user=request.user,
                status=FlowAnalysis.DRAFT,
                created_at=timezone.now()
            )

        serializer = AddStationToFlowAnalysisSerializer(data=request.data)
        if serializer.is_valid():
            station_id = serializer.validated_data['station_id']
            
            # Проверяем, не добавлена ли уже эта станция в черновик
            if FlowAnalysisStation.objects.filter(
                flow_analysis=flow_analysis,
                station_id=station_id
            ).exists():
                return Response(
                    {'error': 'Станция уже добавлена в анализ потока'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Определяем порядок для новой станции
            max_order = FlowAnalysisStation.objects.filter(
                flow_analysis=flow_analysis
            ).aggregate(Max('order'))['order__max']
            
            new_order = 1 if max_order is None else max_order + 1

            # Создаем новую запись
            FlowAnalysisStation.objects.create(
                flow_analysis=flow_analysis,
                station_id=station_id,
                order=new_order
            )

            return Response(
                {'message': 'Станция добавлена в анализ потока'},
                status=status.HTTP_200_OK
            )
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
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }, status=status.HTTP_200_OK)
        return Response(
            {'error': 'Неверные учетные данные'}, 
            status=status.HTTP_400_BAD_REQUEST
        )

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