
from django.contrib import admin
from .models import Station, FlowAnalysis, FlowAnalysisStation

admin.site.register(Station)

@admin.register(FlowAnalysis)
class FlowAnalysisAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'status', 'created_at', 'formed_at', 'ended_at')
    search_fields = ('user__username', 'status')

@admin.register(FlowAnalysisStation)
class FlowAnalysisStationAdmin(admin.ModelAdmin):
    list_display = ('flow_analysis', 'station', 'order')
    search_fields = ('flow_analysis__id', 'station__title')