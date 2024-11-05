from django.contrib import admin
from main import views
from django.urls import path
from rest_framework import routers
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

router = routers.DefaultRouter()

urlpatterns = [
    path('admin/', admin.site.urls),

    # Станции метро (Услуги)
    path('stations/', views.StationListView.as_view(), name='stations-list'),  # список станций (GET)
    path('stations/<int:pk>/', views.StationDetailView.as_view(), name='station-detail'),  # получить станцию (GET)
    path('stations/create/', views.StationDetailView.as_view(), name='station-create'),  # добавление станции (POST)
    path('stations/update/<int:pk>/', views.StationDetailView.as_view(), name='station-update'),  # редактирование станции (PUT)
    path('stations/delete/<int:pk>/', views.StationDetailView.as_view(), name='station-delete'),  # удаление станции (DELETE)

    path('stations/add/', views.AddStationToFlowAnalysisView.as_view(), name='add-station-to-flow-analysis'),  # добавление станции в анализ потока (POST)

    path('stations/image/<int:pk>/', views.StationImageView.as_view(), name='station-add-image'),  # замена/добавление изображения станции (POST)

    # Анализы потоков (Заявки)
    path('flow-analyses/', views.FlowAnalysisListView.as_view(), name='flow-analyses-list'),  # получить анализы потоков (GET)
    path('flow-analyses/<int:pk>/', views.FlowAnalysisDetailView.as_view(), name='flow-analysis-detail'),  # получить конкретный анализ потока (GET)
    path('flow-analyses/create/', views.FlowAnalysisCreateView.as_view(), name='flow-analysis-create'),  # создание анализа потока (POST)
    path('flow-analyses/update/<int:pk>/', views.FlowAnalysisDetailView.as_view(), name='flow-analysis-update'),  # изменение анализа потока (PUT)

    path('flow-analyses/form/<int:pk>/', views.FlowAnalysisFormView.as_view(), name='flow-analysis-form'),  # формирование анализа потока (PUT)
    path('flow-analyses/complete/<int:pk>/', views.FlowAnalysisCompleteView.as_view(), name='flow-analysis-complete'),  # завершить/отклонить анализ потока (PUT)
    path('flow-analyses/delete/<int:pk>/', views.FlowAnalysisDetailView.as_view(), name='flow-analysis-delete'),  # удалить анализ потока (DELETE)

    # Многие-ко-многим (станции в анализе потока)
    path('flow-analyses/<int:flow_analysis_id>/delete-station/<int:station_id>/', views.RemoveStationFromFlowAnalysisView.as_view(), name='delete-station-from-flow-analysis'),  # удалить станцию из анализа потока (DELETE)
    path('flow-analyses/<int:flow_analysis_id>/update-station/<int:station_id>/', views.UpdateStationInFlowAnalysisView.as_view(), name='update-station-in-flow-analysis'),  # изменить информацию о станции в анализе потока (PUT)

    # Пользователи
    path('users/register/', views.UserRegistrationView.as_view(), name='user-register'),  # регистрация пользователя (POST)
    path('users/update/', views.UserUpdateView.as_view(), name='user-update'),  # обновление пользователя (PUT)
    path('users/login/', views.UserLoginView.as_view(), name='user-login'),  # вход пользователя (POST)
    path('users/logout/', views.UserLogoutView.as_view(), name='user-logout'),  # выход пользователя (POST)




    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

]