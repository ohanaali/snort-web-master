from django.db import models
from pcaps.models import Pcap
from settings.models import attackGroup
from .snort_templates import types_list

class SnortRule(models.Model):
    id = models.AutoField(primary_key=True)
    group = models.ForeignKey(attackGroup, blank=True, null=True, on_delete=models.SET_NULL)
    active = models.BooleanField(default=False)
    admin_locked = models.BooleanField(default=False)
    user = models.CharField(max_length=100, blank=True, default=0)
    name = models.CharField(max_length=100)
    type = models.TextField(max_length=30, choices=types_list)
    content = models.TextField(max_length=2048)
    description = models.TextField(max_length=256)
    extra = models.TextField(max_length=256, blank=True)
    location = models.CharField(max_length=256)
    request_ref = models.CharField(max_length=12, blank=True)
    main_ref = models.CharField(max_length=12, blank=True)
    date = models.DateTimeField(auto_now=True)
    pcap_sanity_check = models.ManyToManyField(Pcap, related_name='pcap_sanity_check', blank=True)
    pcap_legal_check = models.ManyToManyField(Pcap, related_name='pcap_legal_check', blank=True)
    objects = models.Manager()

    class Meta:
        ordering = ("name", "type", "date")


