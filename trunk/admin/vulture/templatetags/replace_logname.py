from django import template
from django.template.defaultfilters import stringfilter
from django.utils.text import normalize_newlines
from django.utils.safestring import mark_safe

register = template.Library()
@register.filter
@stringfilter
def replace_logname(value, arg):
    """Replace / by _ in logs"""
    return value.replace(arg, '_')

@register.filter
@stringfilter
def normal_newlines(text):
    """
    Removes all newline characters from a block of text.
    """
    normalized_text = normalize_newlines(text)
    return mark_safe(normalized_text)

