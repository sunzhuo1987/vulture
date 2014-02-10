from django import template
from django.template.defaultfilters import stringfilter

register = template.Library()

@register.filter
@stringfilter
def replace_logname(value, arg):
    """Replace / by _ in logs"""
    return value.replace(arg, '_')
