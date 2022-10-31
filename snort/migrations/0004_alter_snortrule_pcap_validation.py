# Generated by Django 4.1.2 on 2022-10-31 13:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pcaps', '0003_alter_pcap_extra'),
        ('snort', '0003_snortrule_pcap_validation'),
    ]

    operations = [
        migrations.AlterField(
            model_name='snortrule',
            name='pcap_validation',
            field=models.ManyToManyField(blank=True, related_name='validation_pcap', to='pcaps.pcap'),
        ),
    ]
