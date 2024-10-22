# Generated by Django 4.2.16 on 2024-10-21 23:13

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('main', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='flowanalysis',
            options={'managed': True},
        ),
        migrations.AlterModelOptions(
            name='flowanalysisstation',
            options={'managed': True},
        ),
        migrations.AlterModelOptions(
            name='station',
            options={'managed': True},
        ),
        migrations.AlterUniqueTogether(
            name='flowanalysisstation',
            unique_together=set(),
        ),
        migrations.AlterField(
            model_name='flowanalysis',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime.now),
        ),
        migrations.AlterField(
            model_name='flowanalysis',
            name='day_time',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='flowanalysis',
            name='ended_at',
            field=models.DateTimeField(null=True),
        ),
        migrations.AlterField(
            model_name='flowanalysis',
            name='flow',
            field=models.FloatField(null=True),
        ),
        migrations.AlterField(
            model_name='flowanalysis',
            name='formed_at',
            field=models.DateTimeField(null=True),
        ),
        migrations.AlterField(
            model_name='flowanalysis',
            name='moderator',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='moderator_id', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='flowanalysis',
            name='status',
            field=models.CharField(choices=[('draft', 'черновик'), ('formed', 'сформирован'), ('completed', 'завершён'), ('cancelled', 'отклонён'), ('deleted', 'удален')], default='draft', max_length=15),
        ),
        migrations.AlterField(
            model_name='flowanalysis',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='flowanalysisstation',
            name='order',
            field=models.IntegerField(),
        ),
        migrations.AlterField(
            model_name='station',
            name='picture_url',
            field=models.URLField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='station',
            name='status',
            field=models.CharField(choices=[('active', 'действует'), ('deleted', 'удален')], default='active', max_length=15),
        ),
        migrations.AddConstraint(
            model_name='flowanalysisstation',
            constraint=models.UniqueConstraint(fields=('flow_analysis', 'station'), name='unique_flow_analysis_station'),
        ),
        migrations.AlterModelTable(
            name='flowanalysis',
            table='flow_analyses',
        ),
        migrations.AlterModelTable(
            name='flowanalysisstation',
            table='flow_analysis_stations',
        ),
        migrations.AlterModelTable(
            name='station',
            table='stations',
        ),
    ]