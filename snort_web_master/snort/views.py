from django.shortcuts import render
from django.http.response import HttpResponse
from snort.models import SnortRule
import time
# Create your views here.


def get_rule(request, rule_id=None):
    full_rule = SnortRule.objects.get(**{"id": rule_id}).full_rule

    return HttpResponse(full_rule)
