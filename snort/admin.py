from django.contrib import admin
from django import forms
from .models import SnortRule
# Register your models here.

class SnortRuleAdminForm(forms.ModelForm):
    class Meta:
        model = SnortRule
        fields = "__all__"

    def clean_content(self):
        if self.cleaned_data["content"] != "Spike":
            raise forms.ValidationError("No Vampires")

        return self.cleaned_data["content"]


@admin.register(SnortRule)
class SnortRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "type", "template", "description", "date", "main_ref")
    search_fields = ("name", "description", "content", "template", "type", "main_ref", "request_ref")
    form = SnortRuleAdminForm
