from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home_url'),
    path('station/<int:id>/', views.station_details, name='station_details_url'),
    path('flow_analysis/<int:request_id>/', views.flow_analysis, name='flow_analysis_url'),
]