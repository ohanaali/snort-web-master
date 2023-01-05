import os
import time

from django import forms
from .models import SnortRule, SnortRuleViewArray
from .snort_templates import snort_type_to_template, types_list
from .parser import Parser
from django.contrib import messages
from django.utils.html import mark_safe
from django.db import transaction
# Register your models here.
from django.contrib import admin
from django_object_actions import DjangoObjectActions
import subprocess
from settings.models import Setting, keywords
from django.shortcuts import render
from pcaps.admin import verify_legal_pcap

FIELDS = (
    "id", "full_rule", "active", "admin_locked", 'name', "snort_builder", "request_ref", "main_ref", "description",
    "group", "extra", "location", "user", 'pcap_sanity_check', "pcap_legal_check")

BASE_BUILDER_KEY = ("action", "protocol", "srcipallow", "srcip", "srcportallow", "srcpprt", "direction", "dstipallow",
                    "dstportallow", "dstport")
# todo: fix the sig structure: assitent needed
# todo: upload unmanaged rule file

class SnortRuleAdminForm(forms.ModelForm):
    class Meta:
        model = SnortRule
        fields = "__all__"

    def clean_user(self):
        return getattr(self.current_user, self.current_user.USERNAME_FIELD)

    def clean_date(self):
        return self.cleaned_data["date"]

    def clean_type(self):
        if not dict(types_list).get(self.cleaned_data.get("type")):
            raise forms.ValidationError("cant find type, did you forgot it? or forgot to add type to db", code=404)
        return self.cleaned_data.get("type")

    def clean_content(self):
        try:
            parser = Parser(self.data["full_rule"])
            parser.parse_header()
            parser.parse_options()
        except Exception as e:
            raise forms.ValidationError(e)

        return self.data["full_rule"]

    def clean_location(self):
        try:
            if os.path.dirname(self.cleaned_data["location"]) != "":
                os.makedirs(os.path.dirname(self.cleaned_data["location"]), exist_ok=True)
            os.makedirs(os.path.dirname(self.cleaned_data["location"]), exist_ok=True)
            with open(self.cleaned_data["location"], "w") as rule_file:
                rule_file.write(self.cleaned_data["content"])
        except Exception as e:
            forms.ValidationError(e)
        return self.cleaned_data["location"]

    def clean_pcap_sanity_check(self):
        # return self.cleaned_data.get("pcap_validation")
        if not self.cleaned_data.get("pcap_sanity_check"):
            if Setting.objects.get(**{"name": "FORCE_SANITY_CHECK"}).value == "False":
                return self.cleaned_data["pcap_sanity_check"]
            elif Setting.objects.get(**{"name": "FORCE_SANITY_CHECK"}).value == "True":
                raise forms.ValidationError(
                    f"no pcap provided fof sanity check, plase add pcap or edit setting(FORCE_SANITY_CHECK)")
            else:
                raise forms.ValidationError(
                    f"bad configuration setting (FORCE_SANITY_CHECK), pleas edit setting(FORCE_SANITY_CHECK) must be True or False")
        cur_rule = SnortRule()
        cur_rule.content = self.data.get("full_rule")
        cur_rule.location = self.data.get("location")
        cur_rule.group = self.instance.group
        cur_rule.id = self.data.get("id")
        cur_rule.main_ref = self.data.get("main_ref")
        cur_rule.name = self.data.get("name")
        cur_rule.type = self.data.get("type")
        cur_rule.user = self.data.get("user")
        cur_rule.request_ref = self.data.get("request_ref")

        validate_pcap_snort(self.cleaned_data.get("pcap_sanity_check"), cur_rule)
        return self.cleaned_data["pcap_sanity_check"]

    # only admin can activate admin locked rule
    # todo: disable deleted, add field indicate is deleted
    # todo: snort content edit
    def clean_pcap_legal_check(self):
        # return self.cleaned_data.get("pcap_validation")

        if not self.cleaned_data.get("pcap_legal_check"):
            if Setting.objects.get(**{"name": "FORCE_LEGAL_CHECK"}).value == "False":
                return self.cleaned_data["pcap_legal_check"]
            elif Setting.objects.get(**{"name": "FORCE_LEGAL_CHECK"}).value == "True":
                raise forms.ValidationError(
                    f"no pcap provided fof sanity check, plase add pcap or edit setting(FORCE_LEGAL_CHECK)")
            else:
                raise forms.ValidationError(
                    f"bad configuration setting (FORCE_LEGAL_CHECK), pleas edit setting(FORCE_LEGAL_CHECK) must be True or False")

        cur_rule = SnortRule()
        cur_rule.content = self.data.get("content")
        cur_rule.location = self.data.get("location")
        cur_rule.group = self.data.get("group")
        cur_rule.id = self.data.get("id")
        cur_rule.main_ref = self.data.get("main_ref")
        cur_rule.name = self.data.get("name")
        cur_rule.type = self.data.get("type")
        cur_rule.user = self.data.get("user")
        cur_rule.request_ref = self.data.get("request_ref")

        count = validate_pcap_snort(self.cleaned_data.get("pcap_legal_check"), cur_rule)
        max_allowd = self.cleaned_data["MAX_MATCH_ALLOWD"]
        if int(count) > max_allowd:
            self.cleaned_data["admin_locked"] = True
            self.instance.admin_locked = True
            self.instance.save()
            if self.cleaned_data["active"] == True:
                if not self.current_user.is_staff and not self.current_user.is_superuser:
                    raise forms.ValidationError(
                        f"rule is admin locked due to hige number of validations {count}, please contact admin or fix rule\n all changed of an admin locked rull must be approved by admin")
        else:
            self.cleaned_data["admin_locked"] = False
            self.instance.admin_locked = False
            self.instance.save()

        return self.cleaned_data["pcap_legal_check"]

    def clean_active(self):
        if self.instance.active:
            return self.cleaned_data["active"]
        locked = False
        if self.cleaned_data.get("admin_locked") is None:
            locked = self.instance.admin_locked
        else:
            locked = self.cleaned_data.get("admin_locked")
        if self.cleaned_data["active"] == True and locked:
            if not self.current_user.is_staff and not self.current_user.is_superuser:
                raise forms.ValidationError(
                    f"rule is admin locked, please contact admin", code=403)
        return self.cleaned_data["active"]

    @transaction.atomic
    def clean(self):
        self.clean_content()
        # todo:
        """todo:
         3 ) chaneg the snort builder method to have the values in order to build the snort builder or 
             change the snort builder to build it as neaded to allow chages"""
        if self.errors:
            return
        SnortRuleViewArray.objects.filter(snortId=self.instance.id).delete()
        for key, value in self.data.items():
            if key in FIELDS + ('csrfmiddlewaretoken', "_save"):
                continue
            if key in BASE_BUILDER_KEY:
                item_type = key
                location_x = 0
                location_y = 0
            elif "keyword_selection" in key:
                item_type = "keyword_selection"
                location_x = 0
                try:
                    index = key.index("-")
                except:
                    index = len(key)
                location_y = int(key[len("keyword_selection"):index])
                if "-data" in key:
                    item_type += "keyword_selection-data"
            elif "keyword" in key:
                item_type = "keyword"
                try:
                    index = key.index("-", key.index("-") + 1)
                except:
                    index = len(key)
                location_x = int(key[key.index("-") + 1:index])
                location_y = int(key[len("keyword"):key.index("-")])
                if "-data" in key:
                    item_type += "keyword-data"
            SnortRuleViewArray(snortId=self.instance,
                               typeOfItem=item_type,
                               locationX=location_x,
                               locationY=location_y,
                               value=value).save()
        if self.cleaned_data.get("active"):
            pass
            # todo: save to s3
        else:
            pass
            # todo: make sure it is not on prod


def validate_pcap_snort(pcaps, rule):
    stdout = b""

    if not rule.location:
        import re
        rule.location = re.sub(r'[-\s]+', '-', re.sub(r'[^\w\s-]', '',
                                                      rule.name)
                               .strip()
                               .lower())

    with open(rule.location + ".tmp", "w") as rule_file:
        rule_file.write(rule.content)
    failed = True
    for pcap in pcaps:
        try:
            if not verify_legal_pcap("/app/{pcap.pcap_file}"):
                raise Exception(f"illegal pcap file")
            if not os.path.exists(f"/app/{pcap.pcap_file}"):
                raise Exception(f"cant find file /app/{pcap.pcap_file}")
            stdout, stderr = subprocess.Popen(
                ["/home/snorty/snort3/bin/snort", "-R", rule.location + ".tmp", "-r", f"/app/{pcap.pcap_file}", "-A",
                 "fast"], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE).communicate()
            if stdout and not stderr:
                if b"total_alerts: " in stdout:
                    return stdout.split(b"total_alerts: ")[1].split(b"\n")[0]
                else:
                    return 0
        except Exception as e:
            raise forms.ValidationError(f"could not validate rule on {pcap.pcap_file}: {e}", code=405)
    if failed:
        raise Exception("no rules was chosen")
    return stdout


@admin.register(SnortRule)
class SnortRuleAdmin(DjangoObjectActions, admin.ModelAdmin):
    change_actions = ('load_template',)
    changelist_actions = ('load_template',)
    fields = FIELDS
    filter_horizontal = ('pcap_sanity_check', "pcap_legal_check")
    list_display_links = ("name",)
    list_display = ("id", "name", "group", "description", "date", "main_ref")
    search_fields = (
    "active", 'name', "request_ref", "main_ref", "description", "group", "content", "extra", "location", "user")
    form = SnortRuleAdminForm

    def selected_template(self, obj):
        return self.load_template(self, obj)

    def snort_builder(self, obj):
        return mark_safe(self.snort_buider_section.content.decode("utf-8"))

    def full_rule(self, obj):
        test = mark_safe(self.full_rule_js.content.decode("utf-8"))
        rule = obj
        full_rule = snort_type_to_template[dict(types_list)[rule.type]]().get_rule(rule.group.name, sig_name=rule.name,
                                                                                   sig_content=rule.content,
                                                                                   writer_team=rule.group,
                                                                                   sig_writer=rule.user,
                                                                                   main_doc=rule.main_ref,
                                                                                   cur_date=time.time(),
                                                                                   sig_ref=rule.request_ref,
                                                                                   sig_desc=rule.description)
        return test

    def get_form(self, request, *args, **kwargs):
        form = super(SnortRuleAdmin, self).get_form(request, **kwargs)
        form.current_user = request.user
        context = {"actions": keywords.objects.filter(stage="action", avalable="True"),
                   "protocols": keywords.objects.filter(stage="protocol", avalable="True")}
        self.snort_buider_section = render(request, "html/snortBuilder.html", context)
        self.full_rule_js = render(request, "html/full_rule.html", context)
        return form

    def load_template(self, request, obj: SnortRule):
        error = ""
        stdout = ""
        status = messages.ERROR
        try:
            snort_item = obj.first()
        except:
            snort_item = obj
        template_content = snort_type_to_template[dict(types_list)[obj.type]]().rule_string
        # (obj.name,sig_name=obj.name,sig_content=obj.content,writer_team=obj.group.name,sig_writer=obj.user,main_doc=obj.main_ref,cur_date=time.time(),sig_ref=obj.request_ref,sig_desc=obj.description,sid=obj.id)
        obj.template = template_content
        obj.save()
        # return template_content

    load_template.label = "load template"  # optional
    # validate.color = "green"
    readonly_fields = ("id", 'location', "user", "admin_locked", "full_rule", "snort_builder")
    load_template.short_description = "load template to edit view"  # optional
