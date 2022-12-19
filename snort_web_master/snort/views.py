from django.shortcuts import render
from django.http.response import HttpResponse
from snort.models import SnortRule
import time
from snort.admin import snort_type_to_template, types_list
# Create your views here.
def get_rule(request, rule_id=None):
    rule = SnortRule.objects.get(**{"id": rule_id})
    full_rule = snort_type_to_template[dict(types_list)[rule.type]]().get_rule(rule.group.name, sig_name=rule.name,
                                                                               sig_content=rule.content,
                                                                               writer_team=rule.group,
                                                                               sig_writer=rule.user,
                                                                               main_doc=rule.main_ref,
                                                                               cur_date=time.time(),
                                                                               sig_ref=rule.request_ref,
                                                                               sig_desc=rule.description)
    return HttpResponse(full_rule)