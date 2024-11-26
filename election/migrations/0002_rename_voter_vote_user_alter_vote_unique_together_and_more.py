# Generated by Django 5.1.3 on 2024-11-26 20:31

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('election', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RenameField(
            model_name='vote',
            old_name='voter',
            new_name='user',
        ),
        migrations.AlterUniqueTogether(
            name='vote',
            unique_together=set(),
        ),
        migrations.RemoveField(
            model_name='candidate',
            name='manifesto',
        ),
        migrations.AddField(
            model_name='candidate',
            name='votes',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='vote',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='candidate',
            name='position',
            field=models.CharField(choices=[('President', 'President'), ('Vice President', 'Vice President'), ('General Secretary', 'General Secretary'), ('Treasurer', 'Treasurer'), ('PR Officer', 'PR Officer'), ('Technical Coordinator', 'Technical Coordinator'), ('Event Coordinator', 'Event Coordinator'), ('Creative Head', 'Creative Head'), ('Membership Coordinator', 'Membership Coordinator'), ('Training Head', 'Training Head'), ('Web Admin', 'Web Admin'), ('Social Media Manager', 'Social Media Manager'), ('Logistics Head', 'Logistics Head'), ('Outreach Coordinator', 'Outreach Coordinator'), ('Research Lead', 'Research Lead'), ('Alumni Coordinator', 'Alumni Coordinator')], max_length=50),
        ),
        migrations.AlterField(
            model_name='candidate',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='vote',
            name='position',
            field=models.CharField(choices=[('President', 'President'), ('Vice President', 'Vice President'), ('General Secretary', 'General Secretary'), ('Treasurer', 'Treasurer'), ('PR Officer', 'PR Officer'), ('Technical Coordinator', 'Technical Coordinator'), ('Event Coordinator', 'Event Coordinator'), ('Creative Head', 'Creative Head'), ('Membership Coordinator', 'Membership Coordinator'), ('Training Head', 'Training Head'), ('Web Admin', 'Web Admin'), ('Social Media Manager', 'Social Media Manager'), ('Logistics Head', 'Logistics Head'), ('Outreach Coordinator', 'Outreach Coordinator'), ('Research Lead', 'Research Lead'), ('Alumni Coordinator', 'Alumni Coordinator')], max_length=50),
        ),
        migrations.AlterUniqueTogether(
            name='vote',
            unique_together={('user', 'position')},
        ),
    ]
