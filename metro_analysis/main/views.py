from django.shortcuts import get_object_or_404
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.db import models
from django.contrib.auth.tokens import default_token_generator
from .models import Station, FlowAnalysis, FlowAnalysisStation
from .serializers import (
    AddImageSerializer,
    StationSerializer,
    AddStationToFlowAnalysisSerializer,
    StationDetailSerializer,
    StationListSerializer,
    FlowAnalysisStationSerializer,
    FlowAnalysisSerializer,
    PutFlowAnalysisSerializer,
    UserRegistrationSerializer,
    UserUpdateSerializer,
    AuthTokenSerializer,
    AcceptFlowAnalysisSerializer
)
from datetime import datetime
import numpy as np

# Станции метро (Услуги)
class StationListView(APIView):
    def get(self, request):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        search_text = request.GET.get('title', '')
        if search_text:
            stations = Station.objects.filter(title__icontains=search_text, status='active')
        else:
            stations = Station.objects.filter(status='active')


        flow_analysis = FlowAnalysis.objects.filter(user=user, status='draft').first()
        draft_request_id = flow_analysis.id if flow_analysis else None
        count_stations = flow_analysis.stations.count() if flow_analysis else 0

        serializer = StationListSerializer(stations, many=True)
        response = serializer.data

        extra_data = {
            'draft_request_id': draft_request_id,
            'count_stations': count_stations
        }

        if flow_analysis:
            flow_analysis_stations = FlowAnalysisStation.objects.filter(flow_analysis=flow_analysis).order_by('order')
            flow_stations_serializer = FlowAnalysisStationSerializer(flow_analysis_stations, many=True)
            extra_data['stations_in_draft'] = flow_stations_serializer.data

        response.append(extra_data)

        return Response(response, status=status.HTTP_200_OK)

class StationDetailView(APIView):
    def get(self, request, pk):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        station = get_object_or_404(Station, pk=pk)
        serializer = StationDetailSerializer(station)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        serializer = StationDetailSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        station = get_object_or_404(Station, id=pk)
        serializer = StationDetailSerializer(station, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        station = get_object_or_404(Station, pk=pk)
        station.status = 'deleted'
        station.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

class StationImageView(APIView):
    def post(self, request, pk):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        serializer = AddImageSerializer(data=request.data)
        if serializer.is_valid():
            station = get_object_or_404(Station, pk=pk)
            station.picture_url = serializer.validated_data['picture_url']
            station.save()
            return Response(status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class AddStationToFlowAnalysisView(APIView):
    def post(self, request):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        flow_analysis = FlowAnalysis.objects.filter(user=user, status='draft').first()
        if not flow_analysis:
            flow_analysis = FlowAnalysis.objects.create(user=user, status='draft')

        serializer = AddStationToFlowAnalysisSerializer(data=request.data)
        if serializer.is_valid():
            station_id = serializer.validated_data['station_id']
            max_order = FlowAnalysisStation.objects.filter(flow_analysis=flow_analysis).aggregate(models.Max('order'))['order__max'] or 0


            FlowAnalysisStation.objects.create(
                flow_analysis=flow_analysis,
                station_id=station_id,
                order=max_order + 1,
                flow=None  # поле nullable
            )

            return Response(status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Анализы потоков (Заявки)
class FlowAnalysisListView(APIView):
    def get(self, request):
        date = request.GET.get('date', None)
        status_filter = request.GET.get('status', None)

        queryset = FlowAnalysis.objects.exclude(status='deleted').exclude(status='draft')
        if date:
            queryset = queryset.filter(formed_at__gte=date)
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        serializer = FlowAnalysisSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class FlowAnalysisDetailView(APIView):
    def get(self, request, pk):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        flow_analysis = get_object_or_404(FlowAnalysis, pk=pk)
        serializer = FlowAnalysisSerializer(flow_analysis)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        flow_analysis = get_object_or_404(FlowAnalysis, pk=pk)
        serializer = PutFlowAnalysisSerializer(flow_analysis, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        flow_analysis = get_object_or_404(FlowAnalysis, pk=pk)
        flow_analysis.status = 'deleted'
        flow_analysis.ended_at = datetime.now()
        flow_analysis.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

class FlowAnalysisCreateView(APIView):
    def post(self, request):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        flow_analysis = FlowAnalysis.objects.create(
            user=user,
            status='draft',
            created_at=datetime.now()
        )
        serializer = FlowAnalysisSerializer(flow_analysis)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class FlowAnalysisFormView(APIView):
    def put(self, request, pk):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        flow_analysis = get_object_or_404(FlowAnalysis, pk=pk)
        if flow_analysis.status != 'draft':
            return Response({'error': 'Анализ потока не является черновиком'}, status=status.HTTP_400_BAD_REQUEST)

        flow_analysis.formed_at = datetime.now()
        flow_analysis.status = 'formed'
        flow_analysis.save()
        return Response(status=status.HTTP_200_OK)

# вспомогательная функция для потока Пуассона
def calculate_poisson_flow(average_visits, time_of_day):
    if time_of_day == 'morning':
        time_factor = 0.6
    elif time_of_day == 'day':
        time_factor = 1.0
    elif time_of_day == 'evening':
        time_factor = 0.8
    else:
        time_factor = 1.0

    #Вычисление лямбда для распределения Пуассона
    lambda_value = average_visits * time_factor

    #Возвращает случайную величину, распределенную по Пуассону
    return np.random.poisson(lam=lambda_value)


class FlowAnalysisCompleteView(APIView):
    def put(self, request, pk):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        flow_analysis = get_object_or_404(FlowAnalysis, pk=pk)
        serializer = AcceptFlowAnalysisSerializer(data=request.data)
        if flow_analysis.status != 'formed':
            return Response({'error': 'Анализ потока не сформирован'}, status=status.HTTP_400_BAD_REQUEST)

        if serializer.is_valid():
            if serializer.validated_data['accept']:
                flow_analysis.status = 'completed'
                flow_analysis.moderator = user
                flow_analysis.ended_at = datetime.now()

                # вычисление flow для каждой станции
                for station in flow_analysis.stations.all():
                    # Рассчитаваем пуассоновский поток на основе average_visits и day_time
                    station.flow = calculate_poisson_flow(station.station.average_visits, flow_analysis.day_time)
                    station.save()

                flow_analysis.save()
                return Response(status=status.HTTP_200_OK)


            else:
                flow_analysis.status = 'cancelled'
                flow_analysis.moderator = user
                flow_analysis.ended_at = datetime.now()
            flow_analysis.save()
            return Response(status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Многие-ко-многим (станции в анализе потока)
class RemoveStationFromFlowAnalysisView(APIView):
    def delete(self, request, flow_analysis_id, station_id):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        flow_analysis = get_object_or_404(FlowAnalysis, pk=flow_analysis_id)
        FlowAnalysisStation.objects.filter(flow_analysis=flow_analysis, station_id=station_id).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class UpdateStationInFlowAnalysisView(APIView):
    def put(self, request, flow_analysis_id, station_id):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        station_in_flow_analysis = get_object_or_404(FlowAnalysisStation, flow_analysis_id=flow_analysis_id, station_id=station_id)

        if 'order' in request.data:
            station_in_flow_analysis.order = request.data['order']
            station_in_flow_analysis.save()
            return Response(status=status.HTTP_200_OK)
        return Response({'error': 'No order provided'}, status=status.HTTP_400_BAD_REQUEST)

# Пользователи
class UserRegistrationView(APIView):
    def post(self, request):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Instead of returning a token, we just return user info
            return Response({
                'username': user.username,
                'email': user.email
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserUpdateView(APIView):
    def put(self, request):
        # Предопределённый пользователь
        user = User.objects.get(username='newuser')

        serializer = UserUpdateSerializer(instance=user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    def post(self, request):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        # Simulating user login by returning a fixed message
        return Response({
            'message': 'User logged in successfully',
            'username': user.username
        }, status=status.HTTP_200_OK)

class UserLogoutView(APIView):
    def post(self, request):
        # Предопределённый пользователь
        user = User.objects.get(username='user')

        # Simulating user logout by returning a fixed message
        return Response({
            'message': 'User logged out successfully',
            'username': user.username
        }, status=status.HTTP_204_NO_CONTENT)

