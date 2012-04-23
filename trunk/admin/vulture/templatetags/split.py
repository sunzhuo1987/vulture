from django import template
from django.template.defaultfilters import stringfilter

register = template.Library()

@register.filter
def mysplit(value, sep = "."):
    parts = value.split(sep)
    return (parts[0], sep.join(parts[1:]))

