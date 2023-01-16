# Generated by Django 4.1.2 on 2023-01-08 17:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('snort', '0004_snortrule_deleted'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='snortrule',
            name='template',
        ),
        migrations.AddField(
            model_name='snortrule',
            name='is_template',
            field=models.BooleanField(default=False),
        ),
    ]