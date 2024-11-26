from django.db import models
from datetime import datetime
from django.contrib.auth.models import User

class Station(models.Model):
    ACTIVE = "active"
    DELETED = "deleted"
    STATUS_CHOICES = [
        (ACTIVE, "действует"),
        (DELETED, "удален"),
    ]
    title = models.CharField(max_length=255)
    description = models.TextField()
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default=ACTIVE)
    picture_url = models.URLField(max_length=255, null=True)
    line_number = models.IntegerField()
    line_name = models.CharField(max_length=50)
    line_color = models.CharField(max_length=7)
    average_visits = models.IntegerField()  # Среднее количество посетителей в тысячах

    class Meta:
        managed = True
        db_table = 'stations'

class FlowAnalysis(models.Model):
    DRAFT = "draft"
    FORMED = "formed"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    DELETED = "deleted"
    STATUS_CHOICES = [
        (DRAFT, "черновик"),
        (FORMED, "сформирован"),
        (COMPLETED, "завершён"),
        (CANCELLED, "отклонён"),
        (DELETED, "удален"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    moderator = models.ForeignKey(User, null=True, related_name='moderator_id', on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=datetime.now)
    formed_at = models.DateTimeField(null=True)
    ended_at = models.DateTimeField(null=True)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default=DRAFT)
    day_time = models.CharField(max_length=50, null=True)

    class Meta:
        managed = True
        db_table = 'flow_analyses'

class FlowAnalysisStation(models.Model):
    flow_analysis = models.ForeignKey(FlowAnalysis, on_delete=models.CASCADE, related_name='stations')
    station = models.ForeignKey(Station, on_delete=models.CASCADE)
    order = models.IntegerField()
    flow = models.FloatField(null=True)  # Поток посетителей в тысячах

    class Meta:
        managed = True
        db_table = 'flow_analysis_stations'
        constraints = [
            models.UniqueConstraint(fields=['flow_analysis', 'station'], name='unique_flow_analysis_station')
        ]