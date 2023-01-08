from django.db import models

# Create your models here.
class Setting(models.Model):
    """
    Model for site-wide settings.
    """
    name = models.CharField(max_length=200, help_text="Name of site-wide variable")
    value = models.CharField(null=True, blank=True, max_length=100, help_text="Value of site-wide variable that scripts can reference - must be valid JSON")

    def __unicode__(self):
        return self.name


class attackGroup(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(max_length=256)
    objects = models.Manager()

    def __str__(self):
        return self.name

# Create your models here.
class keywords(models.Model):
    """
    Model for site-wide settings.
    """
    name = models.CharField(max_length=200, help_text="Name of site-wide variable")
    stage = models.CharField(null=True, blank=True, max_length=100, help_text="Value of site-wide variable that scripts can reference")
    description = models.CharField(null=True, blank=True, max_length=100, help_text="Value of site-wide variable that scripts can reference")
    # negation = models.CharField(null=True, blank=True, max_length=100,
    #                                help_text="Value of site-wide variable that scripts can reference")
    options = models.CharField(null=True, blank=True, max_length=100,
                                help_text="Value of site-wide variable that scripts can reference")
    avalable = models.CharField(null=True, blank=True, max_length=10,
                                help_text="Value of site-wide variable that scripts can reference")
    def __unicode__(self):
        return self.name