import os
import time

from django.contrib import admin
from django import forms
from .models import SnortRule
from .snort_templates import ipfull, snort_type_to_template, EMPTY_TYPES
from .parser import Parser
# Register your models here.
from django.contrib import admin
from django_object_actions import DjangoObjectActions

# todo: verify the uploded file is pcap
# todo: validate rule on pcap when clicked validate on pcap
# todo: validate rule on pcap when clicked validate on rule
# todo: active directory sync users
class SnortRuleAdminForm(forms.ModelForm):

    class Meta:
        model = SnortRule
        fields = "__all__"

    def clean_type(self):
        if not snort_type_to_template.get(self.cleaned_data["type"]):
            raise forms.ValidationError("cant find type, did you misspled it? or forgot to add type to db")
        return self.cleaned_data["type"]

    def clean_content(self):
        if self.cleaned_data["type"] in EMPTY_TYPES:
            if self.cleaned_data["content"] != "":
                raise forms.ValidationError("rule cannot contain content in the current chosen type")
        else:
            if self.cleaned_data["content"] == "":
                raise forms.ValidationError("rule cannot be empty in the current chosen type")
            else:
                try:
                    Parser(self.cleaned_data["content"])
                except Exception as e:
                    raise forms.ValidationError(e)

        return self.cleaned_data["content"]

    def clean_location(self):
        try:
            if os.path.dirname(self.cleaned_data["location"]) != "":
                os.makedirs(os.path.dirname(self.cleaned_data["location"]), exist_ok=True)
            os.makedirs(os.path.dirname(self.cleaned_data["location"]), exist_ok=True)
            with open(self.cleaned_data["location"], "w") as rule_file:
                rule_file.write(self.cleaned_data["content"])
        except Exception as e:
            forms.ValidationError(e)


@admin.register(SnortRule)
class SnortRuleAdmin(DjangoObjectActions, admin.ModelAdmin):
    def validate(self, request, obj:SnortRule):
        # todo test saved rule vs pcap
        print("validate button pushed", obj.name)
    validate.label = "validate"  # optional
    validate.color = "green"
    validate.short_description = "Submit this article"  # optional


    change_actions = ('validate', )
    changelist_actions = ('validate',)

    list_display = ("name", "type", "template", "description", "date", "main_ref")
    search_fields = ("name", "description", "content", "template", "type", "main_ref", "request_ref")
    form = SnortRuleAdminForm
