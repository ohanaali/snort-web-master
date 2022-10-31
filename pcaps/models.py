from django.db import models

# Create your models here.


class Pcap(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(max_length=256)
    extra = models.TextField(max_length=256)
    location = models.TextField(max_length=256)
    date = models.DateTimeField(auto_now=True)
    objects = models.Manager()

    def __str__(self):
        return self.name

