# Generated by Django 5.1.1 on 2024-11-27 09:46

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('election', '0003_candidate_manifesto'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name='candidate',
            name='manifesto',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='candidate',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]