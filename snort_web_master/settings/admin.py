from django.contrib import admin
from settings.models import Setting
from settings.models import attackGroup
from settings.models import keywords
# Register your models here.

@admin.register(Setting)
class SettingAdmin(admin.ModelAdmin):
    list_display = ['name', 'value']

@admin.register(attackGroup)
class attack_groupAdmin(admin.ModelAdmin):
    list_display = ['name', 'description']


@admin.register(keywords)
class keywords(admin.ModelAdmin):
    list_display = ['name', 'stage']
