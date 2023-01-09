import copy
import os
import time
from functools import partial

import cachetools
from django import forms
from .models import SnortRule, SnortRuleViewArray
from .snort_templates import types_list
from .parser import Parser
from django.utils.encoding import smart_str
from django.http.response import HttpResponse, HttpResponseRedirect
from django.utils.html import mark_safe
from django.db import transaction
from django.views.decorators.cache import never_cache
# Register your models here.
from django.contrib import admin
from django_object_actions import DjangoObjectActions
import subprocess
from settings.models import Setting, keywords
from django.shortcuts import render
from pcaps.admin import verify_legal_pcap

FIELDS = (
    "id", "full_rule", "active", "is_template", "deleted", "admin_locked", 'name', "snort_builder", "request_ref", "main_ref", "description",
    "group", "extra", "location", "user", 'pcap_sanity_check', "pcap_legal_check")

BASE_BUILDER_KEY = ("action", "protocol", "srcipallow", "srcip", "srcportallow", "srcport", "direction", "dstipallow",
                    "dstportallow", "dstport")

INPUT_TYPE = ("srcip" , "srcport", "dstip", "dstport")
from django.core.cache import cache
# todo: upload unmanaged rule file
# todo: export to csv

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

    def clean_is_template(self):
        if not self.cleaned_data.get("is_template"):
            self.cleaned_data["active"] = False
        return self.cleaned_data.get("is_template")

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
        if self.cleaned_data["active"] and locked:
            if not self.current_user.is_staff and not self.current_user.is_superuser:
                raise forms.ValidationError(
                    f"rule is admin locked, please contact admin", code=403)
        return self.cleaned_data["active"]

    @transaction.atomic
    def clean(self):
        try:
            self.instance.user = self.clean_user()
            self.instance.content = self.clean_content()
        except Exception as e:
            self.add_error(None, e)
        rule_keys = []
        self.instance.deleted = False
        if not self.instance.pk and not self.errors:
            self.instance.save()
        SnortRuleViewArray.objects.filter(snortId=None).delete()
        if not self.errors:
            SnortRuleViewArray.objects.filter(snortId=self.instance.id).delete()
        for key, value in self.data.items():
            if key in FIELDS + ('csrfmiddlewaretoken', "_save"):
                continue
            item_type = "select"
            location_x = 0
            location_y = 0
            if "keyword_selection" in key:
                location_x = 0
                try:
                    index = key.index("-")
                except:
                    index = len(key)
                location_y = int(key[len("keyword_selection"):index])
            elif "keyword" in key:
                try:
                    index = key.index("-", key.index("-") + 1)
                except:
                    index = len(key)
                if key[key.index("-") + 1:index] == "not":
                    location_x = 0
                    location_y = 0
                else:
                    location_x = int(key[key.index("-") + 1:index])
                    location_y = int(key[len("keyword"):key.index("-")])
            if "-data" in key or key in INPUT_TYPE:
                item_type = "input"
            rule_keys.append(SnortRuleViewArray(snortId=self.instance,
                               typeOfItem=item_type,
                               locationX=location_x,
                               locationY=location_y,
                               value=value,
                               htmlId=key))
        if not self.errors:
            cache.set(self.instance.id, rule_keys)
            for key in rule_keys:
                key.save()
        else:
            cache.set(self.instance.id, rule_keys)
            return
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
    change_actions = ('clone_rule',)
    # changelist_actions = ('load_template',)
    fields = FIELDS
    filter_horizontal = ('pcap_sanity_check', "pcap_legal_check")
    list_display_links = ("name",)
    list_display = ("id", "active", "name", "group", "description", "date", "is_template")
    search_fields = (
    "active", 'name', "request_ref", "main_ref", "description", "group", "content", "extra", "location", "user")
    form = SnortRuleAdminForm
    actions = ['make_published']

    @admin.action(description='export selected snort to csv')
    def make_published(self, request, queryset):
        response = HttpResponse(
            content_type='application/force-download')  # mimetype is replaced by content_type for django 1.7
        response['Content-Disposition'] = 'attachment; filename=%s' % smart_str("snort_export.csv")
        str_content = "active,date,deleted,description,extra,group,name,id,user,content\n"
        for snort_item in queryset:
            content = snort_item.content.replace('"', "'")
            my_list = [snort_item.active,snort_item.date,snort_item.deleted,snort_item.description,snort_item.extra,snort_item.group,snort_item.name,snort_item.pk,snort_item.user,content]
            for item in my_list:
                if isinstance(item, bool):
                    str_content += str(item) + ","
                    continue
                if not item:
                    str_content += ','
                    continue
                str_content += '"' + str(item) + '",'
                continue
            str_content = str_content[:-1] + "\n"
        response.content = smart_str(str_content)
        # It's usually a good idea to set the 'Content-Length' header too.
        # You can also set any other required headers: Cache-Control, etc.
        return response

    def get_actions(self, request):
        actions = super().get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions
    def snort_builder(self, obj):
        set_rule = cache.get(obj.id)
        if not set_rule:
            set_rule = SnortRuleViewArray.objects.filter(snortId=obj.id)
            cache.set(obj.id, set_rule)
        else:
            cache.set(obj.id, [])
        context = copy.deepcopy(self.context)
        context["build_items"] = set_rule
        snort_buider_section = self.snort_buider_section(context).content.decode("utf-8")
        return mark_safe(snort_buider_section)

    def full_rule(self, obj):
        test = mark_safe(self.full_rule_js.content.decode("utf-8"))
        rule = obj
        full_rule = ""
        return test

    def get_form(self, request, *args, **kwargs):
        form = super(SnortRuleAdmin, self).get_form(request, **kwargs)
        form.current_user = request.user
        context = {"actions": keywords.objects.filter(stage="action", avalable="True"),
                   "protocols": keywords.objects.filter(stage="protocol", avalable="True")}
        self.snort_buider_section = partial(render, request, "html/snortBuilder.html")
        self.full_rule_js = render(request, "html/full_rule.html")
        self.context = context
        return form

    @transaction.atomic
    def clone_rule(self, request, obj: SnortRule):
        new_snort = SnortRule.objects.get(pk=obj.id)
        new_snort.pk = None
        new_snort.template = False
        new_snort.active = False
        new_snort.deleted = False
        new_snort.user = getattr(request.user, request.user.USERNAME_FIELD)
        new_snort.save()
        for keyword in SnortRuleViewArray.objects.filter(snortId=obj.id):
            keyword.pk = None
            keyword.snortId = new_snort
            keyword.save()

        return HttpResponseRedirect(f"/snort/snortrule/{new_snort.pk}/change")

    clone_rule.label = "clone_rule"  # optional

    def get_readonly_fields(self, request, obj=None):
        if obj and (obj.is_template or obj.admin_locked):
            read_only_fields = (
            "id", "active", 'location', "user", "admin_locked", "full_rule", "snort_builder", "deleted")
        else:
            read_only_fields = ("id", 'location', "user", "admin_locked", "full_rule", "snort_builder", "deleted")

        return read_only_fields

    # readonly_fields = ("id", 'location', "user", "admin_locked", "full_rule", "snort_builder", "deleted")
    clone_rule.short_description = "clone rule to a new rule"  # optional
