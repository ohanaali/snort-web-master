from django.shortcuts import render
from django.http.response import HttpResponse, JsonResponse
from snort.models import SnortRule, SnortRuleViewArray
import time
# Create your views here.

def get_rule_keys(request, rule_id=None):
    rule_keywordss = SnortRuleViewArray.objects.filter(**{"snortId": rule_id})
    results = []
    for rule_key in rule_keywordss:
        results.append({"htmlId": rule_key.htmlId,"value": rule_key.value, "typeOfItem": rule_key.typeOfItem,
                    "locationX": rule_key.locationX, "locationY": rule_key.locationY})
    return JsonResponse({"data":results})
def get_rule(request, rule_id=None):
    full_rule = SnortRule.objects.get(**{"id": rule_id}).full_rule

    return HttpResponse(full_rule)
