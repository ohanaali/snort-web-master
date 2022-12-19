import os
import time

from django import forms
from .models import SnortRule
from django.utils.html import format_html
from urllib.parse import quote as urlquote
from .snort_templates import snort_type_to_template, types_list, EMPTY_TYPES
from .parser import Parser
from django.contrib import messages
from django.utils.translation import gettext
# Register your models here.
from django.contrib import admin
from django_object_actions import DjangoObjectActions
import subprocess
from settings.models import Setting

from pcaps.admin import verify_legal_pcap


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
        if not (self.cleaned_data.get("type")):
            return self.clean_type()
        if self.cleaned_data.get("type") in EMPTY_TYPES:
            if self.cleaned_data["content"] != "":
                raise forms.ValidationError("rule cannot contain content in the current chosen type", code=404)
        else:
            if self.cleaned_data["content"] == "":
                raise forms.ValidationError("rule cannot be empty in the current chosen type", code=404)
            else:
                try:
                    rule_template = snort_type_to_template[dict(types_list)[self.cleaned_data.get("type")]]().get_rule("Test",
                                                                                                   sig_name="Test",
                                                                                                   sig_content=self.cleaned_data["content"],
                                                                                                   writer_team="Test",
                                                                                                   sig_writer="test",
                                                                                                   main_doc="0",
                                                                                                   cur_date=time.time(),
                                                                                                   sig_ref="0",
                                                                                                   sig_desc="Test",
                                                                                                   sid=self.current_user.id)
                    parser = Parser(rule_template)
                    parser.parse_header()
                    parser.parse_options()
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
        return self.cleaned_data["location"]

    def clean_pcap_sanity_check(self):
        # return self.cleaned_data.get("pcap_validation")
        if not self.cleaned_data.get("pcap_sanity_check"):
            if Setting.objects.get(**{"name": "FORCE_SANITY_CHECK"}).value == "False":
                return self.cleaned_data["pcap_sanity_check"]
            elif Setting.objects.get(**{"name": "FORCE_SANITY_CHECK"}).value == "True":
                raise forms.ValidationError(f"no pcap provided fof sanity check, plase add pcap or edit setting(FORCE_SANITY_CHECK)")
            else:
                raise forms.ValidationError(
                    f"bad configuration setting (FORCE_SANITY_CHECK), pleas edit setting(FORCE_SANITY_CHECK) must be True or False")
        cur_rule = SnortRule()
        cur_rule.content = self.data.get("content")
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
            locked =  self.instance.admin_locked
        else:
            locked =self.cleaned_data.get("admin_locked")
        if self.cleaned_data["active"] == True and locked:
            if not self.current_user.is_staff and not self.current_user.is_superuser:
                raise forms.ValidationError(
                    f"rule is admin locked, please contact admin", code=403)
        return self.cleaned_data["active"]

    def clean(self):
        cleaned_data = super().clean()
        if not self.errors:
            if self.cleaned_data.get("active"):
                pass
                # todo: save to s3
            else:
                pass
                # todo: make sure it is not on prod

def validate_pcap_snort(pcaps, rule):
    rule_template = snort_type_to_template[dict(types_list)[rule.type]]().get_rule(rule.group.name, sig_name=rule.name, sig_content=rule.content, writer_team=rule.group, sig_writer=rule.user, main_doc=rule.main_ref, cur_date=time.time(), sig_ref=rule.request_ref, sig_desc=rule.description)
    stdout = b""
    if not rule.location:
        import re
        rule.location = re.sub(r'[-\s]+', '-',re.sub(r'[^\w\s-]', '',
                                 rule.name)
                          .strip()
                          .lower())

    with open(rule.location + ".tmp", "w") as rule_file:
        rule_file.write(rule_template)
    failed = True
    for pcap in pcaps:
        try:
            if not verify_legal_pcap("/app/{pcap.pcap_file}"):
                raise Exception(f"illegal pcap file")
            if not os.path.exists(f"/app/{pcap.pcap_file}"):
                raise Exception(f"cant find file /app/{pcap.pcap_file}")
            stdout, stderr = subprocess.Popen(["/home/snorty/snort3/bin/snort", "-R", rule.location + ".tmp", "-r", f"/app/{pcap.pcap_file}", "-A", "fast"], stdout=subprocess.PIPE,
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
    # change_actions = ('validate',)
    # changelist_actions = ('validate',)
    fields = ("active", "admin_locked", 'name', "request_ref", "main_ref", "description", "group", 'type', "content", "extra", "location", "user", 'pcap_sanity_check', "pcap_legal_check")
    filter_horizontal = ('pcap_sanity_check', "pcap_legal_check")
    list_display_links = ("name", )
    list_display = ("id", "name", "group", "type", "description", "date", "main_ref")
    search_fields = ("active", 'name', "request_ref", "main_ref", "description", "group", 'type', "content", "extra", "location", "user")
    form = SnortRuleAdminForm
    def get_form(self, request, *args, ** kwargs):
        form = super(SnortRuleAdmin, self).get_form(request, **kwargs)
        form.current_user = request.user
        return form

    def validate(self, request, obj:SnortRule):
        error = ""
        stdout = ""
        status = messages.ERROR
        try:
            snort_item = obj.first()
        except:
            snort_item = obj
        if os.name == "nt":
            error = f"cannot validate on windows"
            status = messages.ERROR
        else:
            try:
                stdout = validate_pcap_snort(snort_item.pcap_sanity_check.all(), obj)

                stdout = stdout.decode().replace('\n', '<br>')
                status = messages.SUCCESS
                message = "The {name} “{obj}” run validation on {pcap} with results:<br>"+ f"{stdout}"
            except Exception as e:
                error = e
        if error:
            message = "The {name} “{obj}” failed validation on {pcap} due to ERROR:<b>{err}</b>"
        msg_dict = {
            "name": snort_item._meta.verbose_name,
            "obj": format_html('<a href="{}">{}</a>', urlquote(request.path), obj),
            "pcap": "all",
            "err": error
        }
        msg = format_html(
            gettext(message), **msg_dict
        )
        self.message_user(request, msg, status)
        return self.change_view(request, str(snort_item.id))
    # validate.label = "validate on pcaps"  # optional
    # validate.color = "green"
    readonly_fields = ('location', "user", "admin_locked")
    # validate.short_description = "test rule on pcaps"  # optional



