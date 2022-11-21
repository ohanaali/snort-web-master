# Generated by Django 4.1.2 on 2022-11-07 06:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('snort', '0007_remove_snortrule_template'),
    ]

    operations = [
        migrations.AlterField(
            model_name='snortrule',
            name='group',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AlterField(
            model_name='snortrule',
            name='location',
            field=models.CharField(max_length=256),
        ),
        migrations.AlterField(
            model_name='snortrule',
            name='main_ref',
            field=models.CharField(blank=True, max_length=12),
        ),
        migrations.AlterField(
            model_name='snortrule',
            name='request_ref',
            field=models.CharField(blank=True, max_length=12),
        ),
    ]