from django.db import models
from pcaps.models import Pcap

class SnortRule(models.Model):
    group = models.TextField(max_length=100, blank=True)
    name = models.CharField(max_length=100)
    type = models.TextField(max_length=30)
    template = models.TextField(max_length=30)
    content = models.TextField(max_length=2048)
    description = models.TextField(max_length=256)
    extra = models.TextField(max_length=256, blank=True)
    location = models.TextField(max_length=256)
    request_ref = models.TextField(max_length=12, blank=True)
    main_ref = models.TextField(max_length=12, blank=True)
    date = models.DateTimeField(auto_now=True)
    pcap_validation = models.ManyToManyField(Pcap, related_name='validation_pcap', blank=True)
    objects = models.Manager()

    class Meta:
        ordering = ("name", "type", "date")


