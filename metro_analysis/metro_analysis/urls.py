from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from main import views

schema_view = get_schema_view(
    openapi.Info(
        title="Metro Flow Analysis API",
        default_version='v1',
        description="API for managing metro stations and flow analyses",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@metroflow.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),

    # Stations (Услуги)
    path('stations/', views.StationListView.as_view(), name='stations-list'),
    path('stations/<int:pk>/', views.StationDetailView.as_view(), name='station-detail'),
    path('stations/create/', views.StationCreateView.as_view(), name='station-create'),
    path('stations/update/<int:pk>/', views.StationUpdateView.as_view(), name='station-update'),
    path('stations/delete/<int:pk>/', views.StationDeleteView.as_view(), name='station-delete'),
    path('stations/add/<int:pk>/', views.AddStationToFlowAnalysisView.as_view(), name='station-add'),
    path('stations/image/<int:pk>/', views.StationImageView.as_view(), name='station-image'),

    # Flow Analysis (Заявки)
    path('flow_analysis/', views.FlowAnalysisListView.as_view(), name='flow-analyses-list'),
    path('flow_analysis/<int:pk>/', views.FlowAnalysisDetailView.as_view(), name='flow-analysis-detail'),
    path('flow_analysis/create/', views.FlowAnalysisCreateView.as_view(), name='flow-analysis-create'),
    path('flow_analysis/update/<int:pk>/', views.FlowAnalysisUpdateView.as_view(), name='flow-analysis-update'),
    path('flow_analysis/form/<int:pk>/', views.FlowAnalysisFormView.as_view(), name='flow-analysis-form'),
    path('flow_analysis/complete/<int:pk>/', views.FlowAnalysisCompleteView.as_view(), name='flow-analysis-complete'),
    path('flow_analysis/delete/<int:pk>/', views.FlowAnalysisDeleteView.as_view(), name='flow-analysis-delete'),
    path('flow-analyses/<int:flow_analysis_id>/delete-station/<int:station_id>/',
         views.RemoveStationFromFlowAnalysisView.as_view(), name='delete-station-from-flow-analysis'),
    path('flow-analyses/<int:flow_analysis_id>/update-station/<int:station_id>/',
         views.UpdateStationInFlowAnalysisView.as_view(), name='update-station-in-flow-analysis'),

    # Users (Пользователи)
    path('users/register/', views.UserRegistrationView.as_view(), name='user-register'),
    path('users/update/', views.UserUpdateView.as_view(), name='user-update'),
    path('users/login/', views.UserLoginView.as_view(), name='user-login'),
    path('users/logout/', views.UserLogoutView.as_view(), name='user-logout'),
]