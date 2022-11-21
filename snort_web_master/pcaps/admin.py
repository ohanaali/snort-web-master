from django.contrib import admin
from django import forms
import os
from .models import Pcap

@admin.register(Pcap)
class SnortRuleAdmin( admin.ModelAdmin):
    def validate(self, request, obj:Pcap):
        # todo test saved rule vs pcap
        print("validate button pushed", obj.name)
    validate.label = "validate"  # optional
    validate.color = "green"
    validate.short_description = "Submit this article"  # optional


    change_actions = ('validate', )
    changelist_actions = ('validate',)

    list_display = ("name", "description", "pcap_file", "rule_to_validate", "date")
    search_fields = ("name", "description", "pcap_file", "rule_to_validate")
    # form = SnortRuleAdminForm

