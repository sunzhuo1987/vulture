from django import template
from django.template.defaultfilters import stringfilter

register = template.Library()

@register.filter
def mysplit(value, sep = "."):
    if sep not in value:
        return (value,)
    parts = value.split(sep)
    return (parts[0], sep.join(parts[1:]))

