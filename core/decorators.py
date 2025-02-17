import logging
from functools import wraps
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import render, get_object_or_404, redirect, reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.utils.translation import gettext as _
from core.models import Role
from core.forms import RoleForm

# Configure the logger to capture DEBUG-level messages.
logger = logging.getLogger(__name__)

def role_required(role_names):
    """
    Decorator to ensure the user has at least one of the specified roles.
    Superusers bypass this check.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Log basic user information
            logger.debug("Request URL: %s", request.path)
            logger.debug("User: %s", request.user)
            logger.debug(
                "User attributes: is_authenticated=%s, is_superuser=%s, roles=%s",
                request.user.is_authenticated,
                getattr(request.user, 'is_superuser', False),
                list(request.user.roles.all()) if hasattr(request.user, 'roles') else "No roles attribute"
            )
            
            # Check if the user is not authenticated
            if not request.user.is_authenticated:
                logger.debug("User is not authenticated.")
                return HttpResponseForbidden("You do not have the necessary role to access this page.")
            
            # Bypass role check for superusers
            if getattr(request.user, 'is_superuser', False):
                logger.debug("User is superuser. Bypassing role check.")
                return view_func(request, *args, **kwargs)
            
            # Check if the user has at least one of the required roles.
            role_check = any(
                request.user.roles.filter(name=role_name).exists() for role_name in role_names
            )
            logger.debug("Role check for roles %s: %s", role_names, role_check)
            if not role_check:
                return HttpResponseForbidden("You do not have the necessary role to access this page.")
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

# --------------------------
# Role Management Views
# --------------------------

# Role List View (Accessible to Admins and Managers)
@login_required
@role_required(['Admin', 'Manager'])
def role_list(request):
    roles = Role.objects.all()
    return render(request, 'core/role_list.html', {'roles': roles})

# Create Role View (Admin Only)
@login_required
@role_required(['Admin'])
def role_create(request):
    if request.method == 'POST':
        form = RoleForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, _('Role created successfully!'))
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'redirect_url': reverse('role_list')})
            return redirect('role_list')
        else:
            messages.error(request, _('Error creating role.'))
    else:
        form = RoleForm()
    return render(request, 'core/role_form.html', {'form': form, 'title': _('Create New Role')})

# Update Role View (Admin Only)
@login_required
@role_required(['Admin'])
def role_update(request, pk):
    role = get_object_or_404(Role, pk=pk)
    if request.method == 'POST':
        form = RoleForm(request.POST, instance=role)
        if form.is_valid():
            form.save()
            messages.success(request, _('Role updated successfully!'))
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'redirect_url': reverse('role_list')})
            return redirect('role_list')
        else:
            messages.error(request, _('Error updating role.'))
    else:
        form = RoleForm(instance=role)
    return render(request, 'core/role_form.html', {'form': form, 'title': _('Update Role')})

# Delete Role View (Admin Only)
@login_required
@role_required(['Admin'])
def role_delete(request, pk):
    role = get_object_or_404(Role, pk=pk)
    if request.method == 'POST':
        role.delete()
        messages.success(request, _('Role deleted successfully!'))
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'redirect_url': reverse('role_list')})
        return redirect('role_list')
    return render(request, 'core/role_confirm_delete.html', {'role': role})
