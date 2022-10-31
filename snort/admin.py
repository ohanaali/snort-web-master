import time

from django.contrib import admin
from django import forms
from .models import SnortRule
from .snort_templates import ipfull, snort_type_to_template, EMPTY_TYPES
from .parser import Parser
# Register your models here.
from django.contrib import admin
from django_object_actions import DjangoObjectActions

# todo: save file on save click
# todo: save pcap file
# todo: add pacp validation field
# todo: validate rule on pcap when clicked validate (works only on linux)
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


@admin.register(SnortRule)
class SnortRuleAdmin(DjangoObjectActions, admin.ModelAdmin):
    def publish_this(self, request, obj):
        # todo test saved rule vs pcap
        print("Imports button pushed", obj)
    publish_this.label = "validate"  # optional
    publish_this.color = "green"
    publish_this.short_description = "Submit this article"  # optional

    def make_published(modeladmin, request, queryset):
        queryset.update(date=time.time())

    change_actions = ('publish_this', )
    changelist_actions = ('make_published',)

    list_display = ("name", "type", "template", "description", "date", "main_ref")
    search_fields = ("name", "description", "content", "template", "type", "main_ref", "request_ref")
    form = SnortRuleAdminForm
