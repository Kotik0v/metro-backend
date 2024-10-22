from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.contrib.auth.models import User
from django.db import models
from .models import Station, FlowAnalysis, FlowAnalysisStation

from datetime import datetime
@login_required
def home(request):
    search_text = request.GET.get('station_search_name', '')
    if search_text:
        stations = Station.objects.filter(title__icontains=search_text, status='active')
    else:
        stations = Station.objects.filter(status='active')

    current_flow_analysis = FlowAnalysis.objects.filter(user=request.user, status='draft').first()
    count_stations = current_flow_analysis.stations.count() if current_flow_analysis else 0
    request_id = current_flow_analysis.id if current_flow_analysis else 0

    return render(request, 'main/stations.html', {
        'data': {
            'stations': stations,
            'count_stations': count_stations,
            'request_id': request_id
        }
    })

@login_required
def station_details(request, id):
    station = Station.objects.get(id=id)
    return render(request, 'main/station_details.html', {
        'data': {
            'title': station.title,
            'description': station.description,
            'line_number': station.line_number,
            'line_name': station.line_name,
            'line_color': station.line_color,
            'average_visits': station.average_visits,
            'pic': station.picture_url
        }
    })

@login_required
def flow_analysis(request, request_id):
    current_flow_analysis = FlowAnalysis.objects.filter(id=request_id, user=request.user).first()

    if not current_flow_analysis or current_flow_analysis.status == 'deleted':
        return render(request, 'main/flow_analysis.html', {'data': {'stations': [], 'request_id': request_id}})

    station_orders = FlowAnalysisStation.objects.filter(flow_analysis=current_flow_analysis).order_by('order')
    stations = [
        {
            'id': station_order.station.id,
            'order': station_order.order,
            'title': station_order.station.title,
            'pic': station_order.station.picture_url,
            'line_number': station_order.station.line_number,
            'line_name': station_order.station.line_name,
            'line_color': station_order.station.line_color,
            'average_visits': station_order.station.average_visits
        }
        for station_order in station_orders
    ]

    return render(request, 'main/flow_analysis.html', {
        'data': {
            'stations': stations,
            'request_id': request_id
        }
    })

@login_required
def add_station_to_flow_analysis(request):
    if request.method == 'POST':
        current_flow_analysis = FlowAnalysis.objects.filter(user=request.user, status='draft').first()

        if not current_flow_analysis:
            current_flow_analysis = FlowAnalysis.objects.create(
                user=request.user,
                created_at=datetime.now(),
                status='draft'
            )

        station_id = request.POST.get('station_id')
        station = Station.objects.get(id=station_id)

        if not FlowAnalysisStation.objects.filter(flow_analysis=current_flow_analysis, station=station).exists():
            max_order = FlowAnalysisStation.objects.filter(flow_analysis=current_flow_analysis).aggregate(
                max_order=models.Max('order')
            )['max_order'] or 0
            FlowAnalysisStation.objects.create(
                flow_analysis=current_flow_analysis,
                station=station,
                order=max_order + 1
            )

        return redirect('home_url')
    return redirect('home_url')


@login_required
def delete_flow_analysis(request):
    if request.method == 'POST':
        flow_analysis_id = request.POST.get('flow_analysis_id')

        if flow_analysis_id and flow_analysis_id.isdigit():
            flow_analysis_id = int(flow_analysis_id)
            with connection.cursor() as cursor:
                cursor.execute("UPDATE flow_analyses SET status = %s WHERE id = %s", ['deleted', flow_analysis_id])

        return redirect('home_url')
    return redirect('home_url')

@login_required
def remove_station_from_flow_analysis(request, station_id):
    if request.method == 'POST':
        current_flow_analysis = FlowAnalysis.objects.filter(user=request.user, status='draft').first()
        if current_flow_analysis:
            FlowAnalysisStation.objects.filter(flow_analysis=current_flow_analysis, station_id=station_id).delete()
        return redirect('flow_analysis_url', request_id=current_flow_analysis.id)
    return redirect('home_url')