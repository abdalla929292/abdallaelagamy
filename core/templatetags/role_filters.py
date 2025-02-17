# core/templatetags/role_filters.py

from django import template

register = template.Library()

@register.filter
def has_role(user, role_name):
    """
    Returns True if the user has a role with the given name.
    Assumes the user has a ManyToManyField named 'roles'.
    """
    return user.roles.filter(name=role_name).exists()

@register.filter(name='has_any_role')
def has_any_role(user, role_list):
    """
    Checks if the user has any of the roles specified in a comma-separated string.
    """
    roles = [role.strip() for role in role_list.split(',')]
    return user.roles.filter(name__in=roles).exists()
