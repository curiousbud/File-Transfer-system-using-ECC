import os
from django import template

register = template.Library()

@register.filter
def basename(value):
    """Returns the basename of a file path."""
    if value:
        return os.path.basename(value)
    return value

@register.filter
def lookup(dictionary, key):
    """
    Template filter to lookup a value in a dictionary by key
    Usage: {{ dict|lookup:key }}
    """
    return dictionary.get(key, '')
