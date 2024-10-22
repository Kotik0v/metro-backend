from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home_url'),
    path('station/<int:id>/', views.station_details, name='station_details_url'),
    path('flow_analysis/<int:request_id>/', views.flow_analysis, name='flow_analysis_url'),
    path('add_station/', views.add_station_to_flow_analysis, name='add_station'),
    path('del_flow_analysis/', views.delete_flow_analysis, name='del_flow_analysis'),
    path('remove_station/<int:station_id>/', views.remove_station_from_flow_analysis, name='remove_station')
]