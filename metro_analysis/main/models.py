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

    title = models.CharField(max_length=255, null=False)
    description = models.TextField(null=False)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default=ACTIVE)
    picture_url = models.URLField(null=True, max_length=255)
    line_number = models.IntegerField(null=False)
    line_name = models.CharField(max_length=50, null=False)
    line_color = models.CharField(max_length=7, null=False)
    average_visits = models.IntegerField(null=False)

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
    created_at = models.DateTimeField(null=False, default=datetime.now)
    formed_at = models.DateTimeField(null=True)
    ended_at = models.DateTimeField(null=True)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default=DRAFT)
    day_time = models.CharField(max_length=50, null=True)
    flow = models.FloatField(null=True)

    class Meta:
        managed = True
        db_table = 'flow_analyses'


class FlowAnalysisStation(models.Model):
    flow_analysis = models.ForeignKey(FlowAnalysis, on_delete=models.CASCADE, related_name='stations')
    station = models.ForeignKey(Station, on_delete=models.CASCADE)
    order = models.IntegerField(null=False)

    class Meta:
        managed = True
        db_table = 'flow_analysis_stations'
        constraints = [
            models.UniqueConstraint(fields=['flow_analysis', 'station'], name='unique_flow_analysis_station')
        ]