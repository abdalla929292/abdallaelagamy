import base64
import io
from io import BytesIO
import openpyxl
import pandas as pd
import weasyprint
import xlsxwriter
from django.contrib import messages
from django.contrib.auth import login, authenticate, update_session_auth_hash, logout as auth_logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.files.base import ContentFile
from django.db.models import Q, Max
from django.http import JsonResponse, HttpResponseForbidden, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import get_template, render_to_string
from django.urls import reverse
from django.utils.translation import activate
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_exempt
from openpyxl import Workbook
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from weasyprint import HTML, CSS
from .models import *
from core.models import ITWarehouse  # Ensure this model name is correct
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils.timezone import now
from .models import ITRequest
from .forms import ITRequestForm
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .models import AdministrativeRequest

from django.db import transaction
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q, Max
from .models import ITRequest, Department, CustomUser
from .forms import ITRequestForm

from Ticket_System import settings
from .forms import (
    CustomUserCreationForm, CustomUserLoginForm, RoleForm, PositionForm, DepartmentForm,
    RequestTypeForm, TicketForm, CompanySettingsForm, CustomUserUpdateForm, SubRequestTypeForm,
    SubPositionForm, TicketSearchForm, FinancialWarehouseForm, FinancialWarehouseRequestForm,
    HRWarehouseForm, EmployeeDetailsForm, AdministrativeRequestForm, TechnicalOfficeStorageForm,
    ITWarehouseForm, ITRequestForm, MyPossessionForm, ContractorForm, CompanyClearanceForm,
    AccountForm, JournalEntryForm, JournalEntryLineForm, EmployeeAllowanceForm, FinancialAdvanceForm,
    EndOfServiceRewardForm, CRMCustomerForm, CRMLeadForm, ERPPurchaseOrderForm, ERPInvoiceForm,
    AccountingEntryForm, CRMTicketForm, ERPEntryForm, SalaryForm, PasswordChangeForm, WorkshopForm, HealthSafetyForm,
    StartWorkPermitForm
)
from .models import (
    Ticket, Role, CustomUser, Position, Department, RequestType, CompanySettings, SubRequestType,
    SubPosition, FinancialWarehouse, HRWarehouse, EmployeeDetails, AdministrativeRequest,
    TechnicalOfficeStorage, Contractor, CompanyClearance, ITWarehouse, ITRequest, MyPossession, Signature,
    FinancialWarehouseRequest, Account, JournalEntry, JournalEntryLine, EmployeeAllowance,
    FinancialAdvance, EndOfServiceReward, CRMCustomer, CRMLead, ERPPurchaseOrder, ERPInvoice,
    AccountingEntry, CRMTicket, ERPEntry, Salary, 
)

title = _("Title")

import logging
logger = logging.getLogger(__name__)

from django import forms
from .models import Sale
import os
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', '82k3=^yghm_-6febwc^f^d7narv93l+s*4#)swafo70y0$%=&#')

class SaleForm(forms.ModelForm):
    class Meta:
        model = Sale
        fields = ['item_name', 'quantity', 'unit_price', 'customer', 'sale_date', 'notes']


# General Views
def home(request):
    return redirect('ticket_list')


def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            try:
                default_role = Role.objects.get(name='Employee')
                user.roles.add(default_role)
                login(request, user)
                messages.success(request, 'Registration successful. Welcome!')
                return redirect('ticket_list')
            except Role.DoesNotExist:
                messages.error(request, 'Default role not found. Please contact administrator.')
                return redirect('register')
    else:
        form = CustomUserCreationForm()
    return render(request, 'core/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = CustomUserLoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, 'Login successful.')
                return redirect('ticket_list')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = CustomUserLoginForm()
    return render(request, 'core/login.html', {'form': form})

@login_required
def logout_view(request):
    auth_logout(request)
    messages.success(request, 'Logged out successfully.')
    return redirect('login')

@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Password changed successfully!')
            return redirect('ticket_list')
        else:
            messages.error(request, 'Error changing password.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'core/change_password.html', {'form': form})

def set_language(request):
    language = request.GET.get('language', 'en')
    next_url = request.GET.get('next', '/')
    activate(language)
    response = redirect(next_url)
    response.set_cookie(settings.LANGUAGE_COOKIE_NAME, language)
    return response

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.template.loader import render_to_string
from weasyprint import HTML
from .models import AdministrativeRequest

@login_required
def export_work_permit_to_pdf(request):
    work_permits = StartWorkPermit.objects.all()

    # DEBUG: Print queryset to confirm it retrieves data
    print("Work Permits Retrieved:", work_permits)

    context = {'work_permits': work_permits}
    return export_to_pdf(request, 'core/work_permit_pdf.html', context, 'work_permits')

def export_to_pdf(request, template_name, context, file_name):
    """
    Generic function to export any template as a PDF.
    """
    html_string = render_to_string(template_name, context)
    html = HTML(string=html_string, base_url=request.build_absolute_uri('/'))
    pdf = html.write_pdf()

    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'inline; filename="{file_name}.pdf"'
    return response


import logging
from functools import wraps
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils.translation import gettext as _

from core.models import CustomUser, Role
from core.forms import CustomUserCreationForm, CustomUserUpdateForm

# --- Updated Custom Role Decorator ---
import logging
from functools import wraps
from django.http import HttpResponseForbidden
from django.utils.translation import gettext as _

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
            
            # Ensure the user is authenticated.
            if not request.user.is_authenticated:
                logger.debug("User is not authenticated.")
                return HttpResponseForbidden(_("You do not have the necessary role to access this page."))
            
            # Bypass role check for superusers.
            if getattr(request.user, 'is_superuser', False):
                logger.debug("User is superuser. Bypassing role check.")
                return view_func(request, *args, **kwargs)
            
            # Check if the user has at least one of the required roles.
            has_role = any(
                request.user.roles.filter(name=role_name).exists() for role_name in role_names
            )
            logger.debug("Role check for roles %s: %s", role_names, has_role)
            if not has_role:
                return HttpResponseForbidden(_("You do not have the necessary role to access this page."))
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

# --- Updated User Views ---

@login_required
@role_required(['Admin', 'Manager'])  # Use internal role identifiers.
def user_list(request):
    users = CustomUser.objects.all().select_related(
        'department', 
        'position'
    ).prefetch_related('roles')
    return render(request, 'core/user_list.html', {'users': users})

@login_required
@role_required(['Admin'])
def user_create(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            department = form.cleaned_data.get('department')
            position = form.cleaned_data.get('position')
            if department:
                user.department = department
            if position:
                user.position = position
            user.save()
            
            # Handle roles.
            roles = form.cleaned_data.get('roles')
            if roles:
                user.roles.set(roles)
            else:
                try:
                    default_role = Role.objects.get(name='Employee')
                    user.roles.add(default_role)
                except Role.DoesNotExist:
                    pass
            
            form.save_m2m()  # Save many-to-many relationships.
            messages.success(request, _('User created successfully!'))
            return redirect('user_list')
        else:
            for error in form.errors.values():
                messages.error(request, error)
    else:
        form = CustomUserCreationForm()
    
    return render(request, 'core/user_form.html', {
        'form': form,
        'title': _('Create New User')
    })

@login_required
@role_required(['Admin'])
def user_update(request, pk):
    user = get_object_or_404(CustomUser, pk=pk)
    if request.method == 'POST':
        form = CustomUserUpdateForm(request.POST, instance=user)
        if form.is_valid():
            user = form.save(commit=False)
            department = form.cleaned_data.get('department')
            position = form.cleaned_data.get('position')
            if department:
                user.department = department
            if position:
                user.position = position
            user.save()
            
            # Handle roles.
            roles = form.cleaned_data.get('roles')
            if roles:
                user.roles.set(roles)
            
            form.save_m2m()  # Save many-to-many relationships.
            messages.success(request, _('User updated successfully!'))
            return redirect('user_list')
        else:
            for error in form.errors.values():
                messages.error(request, error)
    else:
        form = CustomUserUpdateForm(instance=user)
    
    return render(request, 'core/user_form.html', {
        'form': form,
        'title': _('Update User'),
        'user_obj': user
    })

@login_required
@role_required(['Admin', 'Manager'])
def user_delete(request, pk):
    user = get_object_or_404(CustomUser, pk=pk)
    if request.method == 'POST':
        try:
            user.delete()
            messages.success(request, _('User deleted successfully!'))
        except Exception as e:
            messages.error(request, _('Error deleting user: {}').format(str(e)))
        return redirect('user_list')
    return render(request, 'core/user_confirm_delete.html', {'user': user})


from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden
from django.urls import reverse
from core.models import CustomUser, Role
from core.forms import RoleForm

import logging
from functools import wraps
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from django.utils.translation import gettext as _

from core.models import CustomUser, Role
from core.forms import RoleForm

# --- Custom Role Decorator ---
logger = logging.getLogger(__name__)

import logging
from functools import wraps
from django.http import HttpResponseForbidden
from django.utils.translation import gettext as _

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
            
            # Ensure the user is authenticated.
            if not request.user.is_authenticated:
                logger.debug("User is not authenticated.")
                return HttpResponseForbidden(_("You do not have the necessary role to access this page."))
            
            # Bypass role check for superusers.
            if getattr(request.user, 'is_superuser', False):
                logger.debug("User is superuser. Bypassing role check.")
                return view_func(request, *args, **kwargs)
            
            # Check if the user has at least one of the required roles.
            has_role = any(
                request.user.roles.filter(name=role_name).exists() for role_name in role_names
            )
            logger.debug("Role check for roles %s: %s", role_names, has_role)
            if not has_role:
                return HttpResponseForbidden(_("You do not have the necessary role to access this page."))
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

# --- Manage User Roles (Admin Only) ---
@login_required
@role_required(['Admin'])
def manage_user_roles(request, pk):
    user = get_object_or_404(CustomUser, pk=pk)
    
    if request.method == 'POST':
        role_ids = request.POST.getlist('roles')
        user.roles.clear()
        user.roles.add(*Role.objects.filter(id__in=role_ids))
        messages.success(request, _('User roles updated successfully!'))
        return redirect('user_list')
    
    roles = Role.objects.all()
    return render(request, 'core/manage_user_roles.html', {
        'user': user,
        'roles': roles,
        'user_roles': user.roles.all()
    })

# --- Role List (Only Admin & Manager Can View) ---
import logging
from functools import wraps
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import render, get_object_or_404, redirect, reverse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils.translation import gettext as _
from core.models import Role
from core.forms import RoleForm

logger = logging.getLogger(__name__)

import logging
from functools import wraps
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import render, get_object_or_404, redirect, reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.utils.translation import gettext as _
from core.models import Role
from core.forms import RoleForm

logger = logging.getLogger(__name__)

def role_required(role_names):
    """
    Decorator to ensure the user has at least one of the specified roles.
    Superusers bypass this check.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            logger.debug("Request URL: %s", request.path)
            logger.debug("User: %s", request.user)
            logger.debug(
                "User attributes: is_authenticated=%s, is_superuser=%s, roles=%s",
                request.user.is_authenticated,
                getattr(request.user, 'is_superuser', False),
                list(request.user.roles.all()) if hasattr(request.user, 'roles') else "No roles attribute"
            )
            
            if not request.user.is_authenticated:
                logger.debug("User is not authenticated.")
                return HttpResponseForbidden(_("You do not have the necessary role to access this page."))
            
            if getattr(request.user, 'is_superuser', False):
                logger.debug("User is superuser. Bypassing role check.")
                return view_func(request, *args, **kwargs)
            
            role_check = any(
                request.user.roles.filter(name=role_name).exists() for role_name in role_names
            )
            logger.debug("Role check for roles %s: %s", role_names, role_check)
            if not role_check:
                return HttpResponseForbidden(_("You do not have the necessary role to access this page."))
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

# --- Role List (Accessible to Admins and Managers) ---
@login_required
@role_required(['Admin', 'Manager'])
def role_list(request):
    roles = Role.objects.all()
    return render(request, 'core/role_list.html', {'roles': roles})

# --- Create Role (Admin Only) ---
import logging
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import render, get_object_or_404, redirect, reverse
from django.contrib import messages
from django.utils.translation import gettext as _
from core.models import Role
from core.forms import RoleForm
from core.decorators import role_required

logger = logging.getLogger(__name__)

# --- Role List (Accessible to Admins and Managers) ---
@login_required
@role_required(['Admin', 'Manager'])
def role_list(request):
    roles = Role.objects.all()
    return render(request, 'core/role_list.html', {'roles': roles})

# --- Create Role (Admin Only) ---
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

# --- Update Role (Admin Only) ---
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

# --- Delete Role (Admin Only) ---
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

# Dashboard and Miscellaneous
@login_required
def dashboard(request):
    role = request.user.roles.first().name
    if role == 'Manager':
        tickets = Ticket.objects.filter(assigned_to=request.user).all()
        return render(request, 'core/manager_dashboard.html', {'tickets': tickets})
    elif role == 'Engineer':
        tickets = Ticket.objects.filter(assigned_to=request.user).all()
        return render(request, 'core/engineer_dashboard.html', {'tickets': tickets})
    elif role == 'Technician':
        tickets = Ticket.objects.filter(assigned_to=request.user).all()
        return render(request, 'core/technician_dashboard.html', {'tickets': tickets})
    else:
        return render(request, 'core/user_dashboard.html')


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db.models import Q, Count
from django.db.models.functions import TruncDay, TruncMonth, TruncYear, ExtractWeek, ExtractQuarter, ExtractYear
from .forms import ReportForm
from .models import Report, Ticket, ITRequest, ITWarehouse, HRWarehouse, AdministrativeRequest, FinancialWarehouse, CompanyClearance, StartWorkPermit

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db.models import Q, Count
from django.db.models.functions import TruncDay, TruncMonth, TruncYear, ExtractWeek, ExtractQuarter, ExtractYear
from .forms import ReportForm
from .models import Report, Ticket, ITRequest, ITWarehouse, HRWarehouse, AdministrativeRequest, FinancialWarehouse, CompanyClearance, StartWorkPermit

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db.models import Q, Count
from django.db.models.functions import TruncDay, TruncMonth, TruncYear, ExtractWeek, ExtractQuarter, ExtractYear
from django.contrib.auth import get_user_model
from .forms import ReportForm
from .models import Report, Ticket, ITRequest, ITWarehouse, HRWarehouse, AdministrativeRequest, FinancialWarehouse, CompanyClearance, StartWorkPermit

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db.models import Q, Count
from django.db.models.functions import TruncDay, TruncMonth, TruncYear, ExtractWeek, ExtractQuarter, ExtractYear
from django.contrib.auth import get_user_model
from .forms import ReportForm
from .models import Report, Ticket, ITRequest, ITWarehouse, HRWarehouse, AdministrativeRequest, FinancialWarehouse, CompanyClearance, StartWorkPermit

@login_required
def reports(request):
    """
    Reports dashboard view.
    This page (reports.html) will list all available report types, recent reports, etc.
    """
    reports = Report.objects.filter(created_by=request.user)
    return render(request, 'core/reports.html', {'reports': reports})

@login_required
def feedback(request):
    return render(request, 'core/feedback.html', {'title': 'Feedback'})

from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from .models import Ticket

def update_ticket_status(request, ticket_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)

    if request.method == "POST":
        new_status = request.POST.get("status")
        if new_status in dict(ticket.STATUS_CHOICES):
            ticket.status = new_status
            ticket.save()
            return redirect('/en/tickets/')  # Explicit redirect to ticket list

    return render(request, "tickets/update_status.html", {"ticket": ticket})

@csrf_exempt
@login_required
def update_ticket_order(request):
    if request.method == 'POST':
        order = request.POST.getlist('order[]')
        for index, ticket_id in enumerate(order):
            Ticket.objects.filter(id=ticket_id).update(order=index)
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'fail'})

@login_required
@user_passes_test(lambda u: u.roles.filter(name='Admin').exists())
def inline_edit(request):
    if request.method == 'POST':
        field_name = request.POST.get('field')
        value = request.POST.get('value')
        model_name = request.POST.get('model')
        obj_id = request.POST.get('id')
        model = globals()[model_name]
        obj = get_object_or_404(model, id=obj_id)
        setattr(obj, field_name, value)
        obj.save()
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'fail'})

import base64
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpResponseForbidden
from django.shortcuts import render, get_object_or_404, redirect, reverse
from django.core.files.base import ContentFile
from django.contrib import messages
from django.utils.translation import gettext as _
from core.models import Ticket, Department, RequestType, Signature, CustomUser
from core.forms import TicketForm

@login_required
def ticket_list(request):
    user = request.user
    search_query      = request.GET.get('search', '')
    status_filter     = request.GET.get('status', '')
    department_filter = request.GET.get('department', '')
    date_from         = request.GET.get('date_from', '')
    date_to           = request.GET.get('date_to', '')

    tickets = Ticket.objects.all()

    # Basic filtering.
    if search_query:
        tickets = tickets.filter(title__icontains=search_query)
    if status_filter:
        tickets = tickets.filter(status=status_filter)
    if department_filter:
        tickets = tickets.filter(department_id=department_filter)
    if date_from and date_to:
        tickets = tickets.filter(date_created__range=[date_from, date_to])

    # Role-based filtering:
    # Full access for Admins/Managers/superusers.
    if user.is_superuser or user.roles.filter(name__in=['Admin', 'Manager']).exists():
        pass
    else:
        # All other users see only tickets where they are involved in any key field.
        tickets = tickets.filter(
            Q(applied_by=user) | Q(applied_for=user) | Q(assigned_to=user)
        )

    tickets = tickets.order_by('-date_created')
    context = {
        'tickets': tickets,
        'departments': Department.objects.all(),
        'request_types': RequestType.objects.all(),
        'table_headers': [
            "Ticket No", "Department", "Request Type", "Title", "Description",
            "Applied By", "Applied For", "Assigned To", "Date & Time", "Status",
            "Notes", "Attachment", "Signature", "Actions"
        ],
        'table_fields': [
            'id', 'department.name', 'request_type.name', 'title', 'description',
            'get_applied_by_full_name', 'get_applied_for_full_name', 'get_assigned_to_full_name',
            'date_created', 'get_status_display', 'notes', 'attachment', 'signature'
        ],
        'search_url': 'ticket_list',
        'create_url': 'ticket_create',
        'detail_url': 'ticket_detail',
        'update_url': 'ticket_update',
        'delete_url': 'ticket_delete'
    }
    return render(request, 'core/ticket_list.html', context)

@login_required
def ticket_detail(request, pk):
    ticket = get_object_or_404(Ticket, pk=pk)
    user = request.user

    # Full access for Admins/Managers/superusers.
    if user.is_superuser or user.roles.filter(name__in=['Admin', 'Manager']).exists():
        pass
    else:
        # For other roles, allow viewing only if the user appears in any key field.
        if not (ticket.applied_by == user or ticket.applied_for == user or ticket.assigned_to == user):
            return HttpResponseForbidden("You do not have permission to view this ticket.")

    return render(request, 'core/ticket_detail.html', {'ticket': ticket})

@login_required
def ticket_update_status(request, pk):
    ticket = get_object_or_404(Ticket, pk=pk)
    user = request.user

    # Allow status update for superusers, Admins/Managers, or if the user is the ticket applicant.
    if not (user.is_superuser or user.roles.filter(name__in=['Admin', 'Manager']).exists() or ticket.applied_by == user):
        return HttpResponseForbidden("You do not have permission to update this ticket.")

    if request.method == 'POST':
        status = request.POST.get('status')
        if status in dict(Ticket.STATUS_CHOICES):
            ticket.status = status
            ticket.save()
            messages.success(request, 'Ticket status updated successfully!')
            return redirect('ticket_detail', pk=pk)
    return render(request, 'core/ticket_update_status.html', {'ticket': ticket})

@login_required
def ticket_add_note(request, pk):
    ticket = get_object_or_404(Ticket, pk=pk)
    user = request.user

    # Allow note addition for superusers, Admins/Managers, or if the user is the ticket applicant.
    if not (user.is_superuser or user.roles.filter(name__in=['Admin', 'Manager']).exists() or ticket.applied_by == user):
        return HttpResponseForbidden("You do not have permission to add a note to this ticket.")

    if request.method == 'POST':
        note = request.POST.get('note')
        if note:
            ticket.notes = note
            ticket.save()
            messages.success(request, 'Note added successfully!')
            return redirect('ticket_detail', pk=pk)
    return render(request, 'core/ticket_add_note.html', {'ticket': ticket})

@login_required
def ticket_reassign(request, pk):
    ticket = get_object_or_404(Ticket, pk=pk)
    user = request.user

    # Only allow reassignment for superusers or Admins/Managers.
    if not (user.is_superuser or user.roles.filter(name__in=['Admin', 'Manager']).exists()):
        return HttpResponseForbidden("You do not have permission to reassign this ticket.")

    from core.models import CustomUser
    users = CustomUser.objects.all()
    if request.method == 'POST':
        assigned_to_id = request.POST.get('assigned_to')
        assigned_to = get_object_or_404(CustomUser, pk=assigned_to_id)
        ticket.assigned_to = assigned_to
        ticket.save()
        messages.success(request, 'Ticket reassigned successfully!')
        return redirect('ticket_detail', pk=pk)
    return render(request, 'core/ticket_reassign.html', {'ticket': ticket, 'users': users})

@login_required
def ticket_transfer(request, pk):
    ticket = get_object_or_404(Ticket, pk=pk)
    user = request.user

    # Only allow transfer for superusers or Admins/Managers.
    if not (user.is_superuser or user.roles.filter(name__in=['Admin', 'Manager']).exists()):
        return HttpResponseForbidden("You do not have permission to transfer this ticket.")

    from core.models import CustomUser
    users = CustomUser.objects.all()
    if request.method == 'POST':
        transferred_to_id = request.POST.get('transferred_to')
        transferred_to = get_object_or_404(CustomUser, pk=transferred_to_id)
        ticket.assigned_to = transferred_to
        ticket.save()
        messages.success(request, 'Ticket transferred successfully!')
        return redirect('ticket_detail', pk=pk)
    return render(request, 'core/ticket_transfer.html', {'ticket': ticket, 'users': users})

@login_required
def ticket_create(request):
    # Allow creation for superusers or for privileged roles.
    if not (request.user.is_superuser or 
            request.user.roles.filter(name__in=['Admin', 'Manager', 'Engineer', 'Supervisor', 'DCs']).exists()):
        return HttpResponseForbidden("You do not have permission to create tickets.")

    if request.method == 'POST':
        form = TicketForm(request.POST, request.FILES)
        if form.is_valid():
            ticket = form.save(commit=False)
            ticket.applied_by = request.user
            if request.POST.get('apply_for_others') == "on" and form.cleaned_data.get('applied_for'):
                ticket.applied_for = form.cleaned_data.get('applied_for')
            else:
                ticket.applied_for = request.user
            ticket.save()

            # Handle signature if provided.
            signature_data_url = request.POST.get('signature')
            if signature_data_url:
                fmt, imgstr = signature_data_url.split(';base64,')
                ext = fmt.split('/')[-1]
                signature = Signature(
                    ticket=ticket,
                    image=ContentFile(base64.b64decode(imgstr), name=f'signature_{ticket.id}.{ext}'),
                    name=request.user.get_full_name()
                )
                signature.save()

            messages.success(request, 'Ticket created successfully!')
            return redirect('ticket_list')
        else:
            messages.error(request, 'Error creating ticket. Please check the form.')
    else:
        form = TicketForm()

    return render(request, 'core/ticket_form.html', {'form': form, 'title': 'Create Ticket'})

@login_required
def ticket_update(request, pk):
    ticket = get_object_or_404(Ticket, pk=pk)
    user = request.user

    # Allow update only if the user is a superuser, an Admin/Manager, or the ticket creator.
    if not (user.is_superuser or ticket.applied_by == user or user.roles.filter(name__in=['Admin', 'Manager']).exists()):
        return HttpResponseForbidden("You do not have permission to update this ticket.")

    if request.method == 'POST':
        form = TicketForm(request.POST, request.FILES, instance=ticket)
        if form.is_valid():
            ticket = form.save(commit=False)
            if request.POST.get('apply_for_others') == "on" and form.cleaned_data.get('applied_for'):
                ticket.applied_for = form.cleaned_data.get('applied_for')
            else:
                ticket.applied_for = request.user
            ticket.save()

            signature_data_url = request.POST.get('signature')
            if signature_data_url:
                fmt, imgstr = signature_data_url.split(';base64,')
                ext = fmt.split('/')[-1]
                signature = Signature(
                    ticket=ticket,
                    image=ContentFile(base64.b64decode(imgstr), name=f'signature_{ticket.id}.{ext}'),
                    name=request.user.get_full_name()
                )
                signature.save()

            messages.success(request, 'Ticket updated successfully!')
            return redirect('ticket_detail', pk=ticket.pk)
        else:
            messages.error(request, 'Error updating ticket.')
    else:
        form = TicketForm(instance=ticket)

    return render(request, 'core/ticket_form.html', {'form': form, 'title': 'Edit Ticket'})

@login_required
def ticket_delete(request, pk):
    ticket = get_object_or_404(Ticket, pk=pk)
    user = request.user

    # Allow deletion if the user is a superuser, the ticket creator, or an Admin/Manager.
    if not (user.is_superuser or ticket.applied_by == user or user.roles.filter(name__in=['Admin', 'Manager']).exists()):
        return HttpResponseForbidden("You do not have permission to delete this ticket.")

    if request.method == 'POST':
        ticket.delete()
        messages.success(request, 'Ticket deleted successfully!')
        return redirect('ticket_list')
    return render(request, 'core/ticket_confirm_delete.html', {'ticket': ticket})

# Department Management
@login_required
def department_list(request):
    departments = Department.objects.all()
    return render(request, 'core/department_list.html', {'departments': departments})

@login_required
def department_create(request):
    if request.method == 'POST':
        form = DepartmentForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Department created successfully!')
            return redirect('department_list')
        else:
            messages.error(request, 'Error creating department.')
    else:
        form = DepartmentForm()
    return render(request, 'core/department_form.html', {'form': form, 'title': 'Create New Department'})

@login_required
def department_update(request, pk):
    department = get_object_or_404(Department, pk=pk)
    if request.method == 'POST':
        form = DepartmentForm(request.POST, instance=department)
        if form.is_valid():
            form.save()
            messages.success(request, 'Department updated successfully!')
            return redirect('department_list')
        else:
            messages.error(request, 'Error updating department.')
    else:
        form = DepartmentForm(instance=department)
    return render(request, 'core/department_form.html', {'form': form, 'title': 'Update Department'})

@login_required
def department_delete(request, pk):
    department = get_object_or_404(Department, pk=pk)
    if request.method == 'POST':
        department.delete()
        messages.success(request, 'Department deleted successfully!')
        return redirect('department_list')
    return render(request, 'core/department_confirm_delete.html', {'department': department})

# Request Type Management
@login_required
def request_type_list(request):
    request_types = RequestType.objects.prefetch_related('sub_request_types').all()
    return render(request, 'core/request_type_list.html', {'request_types': request_types})

@login_required
def request_type_create(request):
    if request.method == 'POST':
        form = RequestTypeForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Request type created successfully!')
            return redirect('request_type_list')
        else:
            messages.error(request, 'Error creating request type.')
    else:
        form = RequestTypeForm()
    return render(request, 'core/request_type_form.html', {'form': form, 'title': 'Create New Request Type'})

@login_required
def request_type_update(request, pk):
    request_type = get_object_or_404(RequestType, pk=pk)
    if request.method == 'POST':
        form = RequestTypeForm(request.POST, instance=request_type)
        if form.is_valid():
            form.save()
            messages.success(request, 'Request type updated successfully!')
            return redirect('request_type_list')
        else:
            messages.error(request, 'Error updating request type.')
    else:
        form = RequestTypeForm(instance=request_type)
    return render(request, 'core/request_type_form.html', {'form': form, 'title': 'Update Request Type'})

@login_required
def request_type_delete(request, pk):
    request_type = get_object_or_404(RequestType, pk=pk)
    if request.method == 'POST':
        request_type.delete()
        messages.success(request, 'Request type deleted successfully!')
        return redirect('request_type_list')
    return render(request, 'core/request_type_confirm_delete.html', {'request_type': request_type})

# Sub Request Type Management
@login_required
def sub_request_type_list(request, request_type_id):
    sub_request_types = SubRequestType.objects.filter(main_request_type_id=request_type_id)
    data = [{'id': sub_request_type.id, 'name': sub_request_type.name} for sub_request_type in sub_request_types]
    return JsonResponse(data, safe=False)

@login_required
def sub_request_type_create(request, request_type_id):
    main_request_type = get_object_or_404(RequestType, pk=request_type_id)
    if request.method == 'POST':
        form = SubRequestTypeForm(request.POST)
        if form.is_valid():
            sub_request_type = form.save(commit=False)
            sub_request_type.main_request_type = main_request_type
            sub_request_type.save()
            messages.success(request, 'Sub-request type created successfully!')
            return redirect('request_type_list')
        else:
            messages.error(request, 'Error creating sub-request type.')
    else:
        form = SubRequestTypeForm(initial={'main_request_type': main_request_type})
    return render(request, 'core/sub_request_type_form.html', {'form': form, 'title': 'Create Sub-request Type'})

@login_required
def sub_request_type_update(request, pk):
    sub_request_type = get_object_or_404(SubRequestType, pk=pk)
    if request.method == 'POST':
        form = SubRequestTypeForm(request.POST, instance=sub_request_type)
        if form.is_valid():
            form.save()
            messages.success(request, 'Sub-request type updated successfully!')
            return redirect('sub_request_type_list', request_type_id=sub_request_type.main_request_type.id)
        else:
            messages.error(request, 'Error updating sub-request type.')
    else:
        form = SubRequestTypeForm(instance=sub_request_type)
    return render(request, 'core/sub_request_type_form.html', {'form': form, 'title': 'Update Sub-request Type'})

@login_required
def sub_request_type_delete(request, pk):
    sub_request_type = get_object_or_404(SubRequestType, pk=pk)
    if request.method == 'POST':
        sub_request_type.delete()
        messages.success(request, 'Sub-request type deleted successfully!')
        return redirect('sub_request_type_list')
    return render(request, 'core/sub_request_type_confirm_delete.html', {'sub_request_type': sub_request_type})

@login_required
def get_sub_request_types(request, request_type_id):
    sub_request_types = SubRequestType.objects.filter(main_request_type_id=request_type_id)
    data = [{'id': srt.id, 'name': srt.name} for srt in sub_request_types]
    return JsonResponse(data, safe=False)

@login_required
def get_request_types(request, department_id):
    request_types = RequestType.objects.filter(department_id=department_id)
    data = [{'id': rt.id, 'name': rt.name} for rt in request_types]
    return JsonResponse(data, safe=False)

import logging
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from django.utils.translation import gettext as _

from core.models import Position, SubPosition
from core.forms import PositionForm, SubPositionForm
from core.decorators import role_required  # Make sure this is imported from your decorators module

# Configure the logger (ensure your logging config captures DEBUG messages)
logger = logging.getLogger(__name__)

# ---------------------------
# Position Management Views
# ---------------------------

@login_required
@role_required(['Admin', 'Manager'])
def position_list(request):
    logger.debug("Accessing position_list. Request path: %s", request.path)
    positions = Position.objects.prefetch_related('sub_positions').all()
    return render(request, 'core/position_list.html', {'positions': positions})


@login_required
@role_required(['Admin'])
def position_create(request):
    logger.debug("Accessing position_create. Request method: %s", request.method)
    if request.method == 'POST':
        logger.debug("POST data: %s", request.POST)
        form = PositionForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, _('Position created successfully!'))
            return redirect('position_list')
        else:
            logger.debug("PositionForm errors on create: %s", form.errors)
            messages.error(request, _('Error creating position.'))
    else:
        form = PositionForm()
    return render(request, 'core/position_form.html', {
        'form': form,
        'title': _('Create New Position')
    })


@login_required
@role_required(['Admin'])
def position_update(request, pk):
    position = get_object_or_404(Position, pk=pk)
    logger.debug("Accessing position_update for Position id: %s, Request method: %s", pk, request.method)
    if request.method == 'POST':
        logger.debug("POST data: %s", request.POST)
        form = PositionForm(request.POST, instance=position)
        if form.is_valid():
            form.save()
            messages.success(request, _('Position updated successfully!'))
            return redirect('position_list')
        else:
            logger.debug("PositionForm errors on update: %s", form.errors)
            messages.error(request, _('Error updating position.'))
    else:
        form = PositionForm(instance=position)
    return render(request, 'core/position_form.html', {
        'form': form,
        'title': _('Update Position')
    })


@login_required
@role_required(['Admin'])
def position_delete(request, pk):
    position = get_object_or_404(Position, pk=pk)
    logger.debug("Accessing position_delete for Position id: %s, Request method: %s", pk, request.method)
    if request.method == 'POST':
        try:
            position.delete()
            messages.success(request, _('Position deleted successfully!'))
            logger.debug("Position deleted successfully.")
        except Exception as e:
            logger.error("Error deleting position: %s", str(e))
            messages.error(request, _('Error deleting position: {}').format(str(e)))
        return redirect('position_list')
    return render(request, 'core/position_confirm_delete.html', {'position': position})


# -------------------------------
# Sub-Position Management Views
# -------------------------------

@login_required
def sub_position_list(request):
    logger.debug("Accessing sub_position_list. Request path: %s", request.path)
    sub_positions = SubPosition.objects.all()
    return render(request, 'core/sub_position_list.html', {'sub_positions': sub_positions})


@login_required
def sub_position_create(request, position_id):
    main_position = get_object_or_404(Position, pk=position_id)
    logger.debug("Accessing sub_position_create for Position id: %s, Request method: %s", position_id, request.method)
    if request.method == 'POST':
        logger.debug("POST data for sub_position_create: %s", request.POST)
        form = SubPositionForm(request.POST)
        if form.is_valid():
            sub_position = form.save(commit=False)
            sub_position.main_position = main_position
            sub_position.save()
            messages.success(request, _('Sub-position created successfully!'))
            return redirect('position_list')
        else:
            logger.debug("SubPositionForm errors on create: %s", form.errors)
            messages.error(request, _('Error creating sub-position.'))
    else:
        form = SubPositionForm(initial={'main_position': main_position})
    return render(request, 'core/sub_position_form.html', {
        'form': form,
        'title': _('Create Sub-position')
    })


@login_required
def sub_position_update(request, pk):
    sub_position = get_object_or_404(SubPosition, pk=pk)
    logger.debug("Accessing sub_position_update for SubPosition id: %s, Request method: %s", pk, request.method)
    if request.method == 'POST':
        logger.debug("POST data for sub_position_update: %s", request.POST)
        form = SubPositionForm(request.POST, instance=sub_position)
        if form.is_valid():
            form.save()
            messages.success(request, _('Sub-position updated successfully!'))
            return redirect('sub_position_list')
        else:
            logger.debug("SubPositionForm errors on update: %s", form.errors)
            messages.error(request, _('Error updating sub-position.'))
    else:
        form = SubPositionForm(instance=sub_position)
    return render(request, 'core/sub_position_form.html', {
        'form': form,
        'title': _('Update Sub-position')
    })


@login_required
def sub_position_delete(request, pk):
    sub_position = get_object_or_404(SubPosition, pk=pk)
    logger.debug("Accessing sub_position_delete for SubPosition id: %s, Request method: %s", pk, request.method)
    if request.method == 'POST':
        try:
            sub_position.delete()
            messages.success(request, _('Sub-position deleted successfully!'))
            logger.debug("Sub-position deleted successfully.")
        except Exception as e:
            logger.error("Error deleting sub-position: %s", str(e))
            messages.error(request, _('Error deleting sub-position: {}').format(str(e)))
        return redirect('sub_position_list')
    return render(request, 'core/sub_position_confirm_delete.html', {'sub_position': sub_position})

from django.core.exceptions import PermissionDenied

@login_required
def company_settings(request):
    # Check if user is admin
    if not request.user.is_superuser:  # Or request.user.is_staff for staff access
        raise PermissionDenied("You don't have permission to access this page.")
    
    settings = CompanySettings.objects.first()
    if request.method == 'POST':
        form = CompanySettingsForm(request.POST, request.FILES, instance=settings)
        if form.is_valid():
            form.save()
            messages.success(request, 'Settings updated successfully!')
            return redirect('company_settings')
        else:
            messages.error(request, 'Error saving company settings.')
    else:
        form = CompanySettingsForm(instance=settings)
    return render(request, 'core/company_settings.html', 
                 {'form': form, 'title': 'Company Settings', 'company_settings': settings})

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import HttpResponseForbidden
from django.db.models import Q
from core.models import FinancialWarehouse, CustomUser
from core.forms import FinancialWarehouseForm
import base64

# View for listing Financial Warehouse items.
@login_required
def financial_warehouse_list(request):
    query = request.GET.get('q', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    name = request.GET.get('name', '')

    user = request.user
    # Determine if the user is a Worker.
    is_worker = user.roles.filter(name='Worker').exists()
    # For full permission, check if the user is in one of these roles:
    is_admin = user.roles.filter(name__in=['Admin', 'Supervisors', 'Warehouse Supervisor']).exists()

    if is_worker:
        items = FinancialWarehouse.objects.filter(item_with=user)
    else:
        items = FinancialWarehouse.objects.all()

    # Apply filtering conditions.
    if query:
        items = items.filter(
            Q(item_no__icontains=query) |
            Q(item_name__icontains=query) |
            Q(description__icontains=query) |
            Q(storing_location__icontains=query) |
            Q(serial_number__icontains=query)
        )
    if date_from and date_to:
        items = items.filter(date_received__range=[date_from, date_to])
    if name:
        items = items.filter(item_name__icontains=name)

    # Get all users (for assignment purposes).
    users = CustomUser.objects.all().order_by('first_name', 'last_name')

    context = {
        'items': items,
        'query': query,
        'date_from': date_from,
        'date_to': date_to,
        'name': name,
        'is_worker': is_worker,
        'is_admin': is_admin,
        'users': users,
    }
    return render(request, 'core/financial_warehouse_list.html', context)

# View to assign an item.
@login_required
def assign_item(request, pk):
    item = get_object_or_404(FinancialWarehouse, pk=pk)
    # Only allow users with Admin, Supervisors, or Warehouse Supervisor roles.
    if not request.user.roles.filter(name__in=['Admin', 'Supervisors', 'Warehouse Supervisor']).exists():
        return HttpResponseForbidden("You do not have permission to assign items.")
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        if user_id:
            assign_to = get_object_or_404(CustomUser, id=user_id)
            item.item_with = assign_to
            item.is_taken = True
            item.save()
            messages.success(request, f'Item assigned to {assign_to.get_full_name()}')
        return redirect('financial_warehouse_list')

# View to take an item.
@login_required
def take_item(request, pk):
    item = get_object_or_404(FinancialWarehouse, pk=pk)
    # Check if already taken.
    if item.is_taken:
        messages.error(request, 'This item has already been taken.')
        return redirect('financial_warehouse_list')
    item.taken_by = request.user
    item.is_taken = True
    item.save()
    messages.success(request, 'Item taken successfully!')
    return redirect('financial_warehouse_list')

# View to create a new Financial Warehouse item.
@login_required
@user_passes_test(lambda u: u.roles.filter(name__in=['Admin', 'Supervisors', 'Warehouse Supervisor']).exists(), login_url='/forbidden/')
def financial_warehouse_create(request):
    if request.method == 'POST':
        form = FinancialWarehouseForm(request.POST, request.FILES)
        if form.is_valid():
            instance = form.save(commit=False)
            instance.created_by = request.user
            instance.save()
            messages.success(request, 'Item added successfully!')
            return redirect('financial_warehouse_list')
        else:
            messages.error(request, 'Error adding item. Please check the form.')
    else:
        form = FinancialWarehouseForm()
    return render(request, 'core/financial_warehouse_form.html', {'form': form, 'title': 'Add Item'})

# View to update a Financial Warehouse item.
@login_required
@user_passes_test(lambda u: u.roles.filter(name__in=['Admin', 'Supervisors', 'Warehouse Supervisor']).exists(), login_url='/forbidden/')
def financial_warehouse_update(request, pk):
    item = get_object_or_404(FinancialWarehouse, pk=pk)
    # Prevent update if the item is locked.
    if item.is_locked:
        messages.error(request, 'This item is locked and cannot be modified.')
        return redirect('financial_warehouse_list')
    if request.method == 'POST':
        form = FinancialWarehouseForm(request.POST, request.FILES, instance=item)
        if form.is_valid():
            try:
                form.save()
                messages.success(request, 'Item updated successfully!')
                return redirect('financial_warehouse_list')
            except PermissionError:
                messages.error(request, 'This item is locked and cannot be modified.')
        else:
            messages.error(request, 'Error updating item. Please check the form.')
    else:
        form = FinancialWarehouseForm(instance=item)
    return render(request, 'core/financial_warehouse_form.html', {
        'form': form,
        'title': 'Edit Item',
        'is_locked': item.is_locked
    })

# View to delete a Financial Warehouse item.
@login_required
@user_passes_test(lambda u: u.roles.filter(name__in=['Admin', 'Supervisors', 'Warehouse Supervisor']).exists(), login_url='/forbidden/')
def financial_warehouse_delete(request, pk):
    messages.error(request, 'Deletion is not allowed in the Financial Warehouse system.')
    return redirect('financial_warehouse_list')


# HR Warehouse Management
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from core.models import HRWarehouse

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import HttpResponseForbidden
from core.models import HRWarehouse
from core.forms import HRWarehouseForm

from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages

from core.models import HRWarehouse
from core.forms import HRWarehouseForm

@login_required
def hr_warehouse_list(request):
    user = request.user
    items = HRWarehouse.objects.all()

    # Determine the correct field for ownership
    assigned_field = "current_driver"  # Change this if another field is correct

    # Permissions Handling:
    # Users with roles 'Admin' or 'Supervisors' see all items.
    # Others only see items where they are the assigned current_driver.
    if not user.roles.filter(name__in=['Admin', 'Supervisors']).exists():
        items = items.filter(**{assigned_field: user})

    context = {
        'title': "HR Warehouse",
        'search_url': 'hr_warehouse_list',
        'create_url': 'hr_warehouse_create',
        'table_headers': [
            "Item No.", "Item Type", "Plate Number", "Last Checkup Date", "Duration of Checkup", "End Checkup Date",
            "License Last Checkup", "Duration of License", "End License Date", "Insurance Date Renew",
            "Duration of Insurance", "End Insurance Date", "Current Driver", "Location", "Traffic Violation Price", "Actions"
        ],
        'table_fields': [
            'item_no', 'item_type', 'plate_number', 'last_checkup_date', 'duration_of_checkup', 'end_checkup_date',
            'license_last_checkup', 'duration_of_license', 'end_license_date', 'insurance_date_renew',
            'duration_of_insurance', 'end_insurance_date', 'current_driver', 'location', 'traffic_violation_price'
        ],
        'items': items,
    }
    return render(request, 'core/hr_warehouse_list.html', context)


@login_required
@user_passes_test(lambda u: u.roles.filter(name__in=['Admin', 'Supervisors']).exists(), login_url='/forbidden/')
def hr_warehouse_create(request):
    if request.method == 'POST':
        form = HRWarehouseForm(request.POST, request.FILES)
        if form.is_valid():
            item = form.save(commit=False)
            item.created_by = request.user
            item.save()
            messages.success(request, 'Item added successfully!')
            return redirect('hr_warehouse_list')
        else:
            messages.error(request, 'Error adding item. Please check the form.')
    else:
        form = HRWarehouseForm()
    
    return render(request, 'core/hr_warehouse_form.html', {'form': form, 'title': 'Add New Item'})


@login_required
@user_passes_test(lambda u: u.roles.filter(name__in=['Admin', 'Supervisors']).exists(), login_url='/forbidden/')
def hr_warehouse_update(request, pk):
    item = get_object_or_404(HRWarehouse, pk=pk)

    if request.method == 'POST':
        form = HRWarehouseForm(request.POST, request.FILES, instance=item)
        if form.is_valid():
            form.save()
            messages.success(request, 'Item updated successfully!')
            return redirect('hr_warehouse_list')
        else:
            messages.error(request, 'Error updating item. Please check the form.')
    else:
        form = HRWarehouseForm(instance=item)
    
    return render(request, 'core/hr_warehouse_form.html', {'form': form, 'title': 'Edit Item'})


@login_required
@user_passes_test(lambda u: u.roles.filter(name='Admin').exists(), login_url='/forbidden/')
def hr_warehouse_delete(request, pk):
    item = get_object_or_404(HRWarehouse, pk=pk)
    if request.method == 'POST':
        item.delete()
        messages.success(request, 'Item deleted successfully!')
        return redirect('hr_warehouse_list')
    return render(request, 'core/hr_warehouse_confirm_delete.html', {'item': item})


# Employee Details Management
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from core.models import EmployeeDetails

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponseForbidden
from django.db.models import Q
from datetime import datetime, timedelta
from core.models import EmployeeDetails
from core.forms import EmployeeDetailsForm

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.contrib import messages
from datetime import datetime, timedelta
from core.models import EmployeeDetails
from core.forms import EmployeeDetailsForm

from datetime import timedelta
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages

from core.models import EmployeeDetails
from core.forms import EmployeeDetailsForm

@login_required
def employee_details_list(request):
    """ Display employee details with role-based access. """
    user = request.user
    items = EmployeeDetails.objects.all()

    # Permissions Handling:
    # Only Admins and Supervisors can view all employee details.
    # Other users (e.g. Employees) see only the details they created.
    if not user.roles.filter(name__in=['Admin', 'Supervisors']).exists():
        items = items.filter(created_by=user)

    context = {
        'title': "Employee Details",
        'search_url': 'employee_details_list',
        'create_url': 'employee_details_create',
        'table_headers': [
            "Employee No.", "Iqama ID", "Name", "Profession", "Date of Birth", "Nationality", "Passport No.", 
            "Name on Passport", "Phone Number in KSA", "Relative Name", "Relative Phone Number", "ID Renew Date", 
            "Duration", "ID End Date", "Actions"
        ],
        'table_fields': [
            'employee_no', 'iqama_id_no', 'name', 'profession', 'date_of_birth', 'nationality', 'passport_no',
            'name_on_passport', 'phone_number_ksa', 'relative_name', 'relative_phone_number', 'id_renew_date',
            'duration', 'id_end_date'
        ],
        'items': items,
    }
    return render(request, 'core/employee_details_list.html', context)


@login_required
def employee_details_create(request):
    # Only users with these roles are considered "admins" for employee details.
    admin_roles = ['Admin', 'Supervisors']

    # Workers are not allowed to create employee details.
    if request.user.roles.filter(name='Worker').exists():
        return HttpResponseForbidden("Workers cannot create employee details.")

    if request.method == "POST":
        form = EmployeeDetailsForm(request.POST, request.FILES, request=request)
        if form.is_valid():
            instance = form.save(commit=False)
            instance.created_by = request.user

            # If the user is not an Admin or Supervisor, assign the record to themselves.
            if not request.user.roles.filter(name__in=admin_roles).exists():
                instance.user = request.user  

            # Ensure profession is assigned if not provided.
            if not instance.profession:
                instance.profession = getattr(request.user, 'profession', None)

            # Auto-calculate ID End Date if both ID renew date and duration are provided.
            if instance.id_renew_date and instance.duration:
                instance.id_end_date = instance.id_renew_date + timedelta(days=instance.duration * 30)

            instance.save()
            messages.success(request, "Employee details saved successfully!")
            return redirect("employee_details_list")
        else:
            messages.error(request, "Error saving employee details. Please check the form.")
    
    else:
        form = EmployeeDetailsForm(request=request)

    return render(request, "core/employee_details_form.html", {
        "form": form, 
        "title": "Add Employee Details"
    })


@login_required
def employee_details_update(request, pk):
    """ Handle updating an existing Employee Details record """
    item = get_object_or_404(EmployeeDetails, pk=pk)

    # Permissions Handling:
    # Only Admins and Supervisors can update any record.
    # Others can only update their own record.
    if not request.user.roles.filter(name__in=['Admin', 'Supervisors']).exists():
        if item.created_by != request.user:
            return HttpResponseForbidden("You do not have permission to edit this employee detail.")

    if request.method == 'POST':
        form = EmployeeDetailsForm(request.POST, request.FILES, instance=item, request=request)
        if form.is_valid():
            item = form.save(commit=False)

            # Ensure profession is always assigned.
            if hasattr(request.user, 'profession') and not item.profession:
                item.profession = request.user.profession

            # Calculate ID End Date if needed.
            if item.id_renew_date and item.duration:
                item.id_end_date = item.id_renew_date + timedelta(days=30 * item.duration)

            item.save()
            messages.success(request, 'Employee details updated successfully!')
            return redirect('employee_details_list')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = EmployeeDetailsForm(instance=item, request=request)

    return render(request, 'core/employee_details_form.html', {
        'form': form, 
        'title': 'Edit Employee'
    })


@login_required
def employee_details_delete(request, pk):
    item = get_object_or_404(EmployeeDetails, pk=pk)
    if request.method == 'POST':
        item.delete()
        messages.success(request, 'Employee details deleted successfully!')
        return redirect('employee_details_list')
    return render(request, 'core/employee_details_confirm_delete.html', {'item': item})

import base64
import json
from datetime import timedelta
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import render, get_object_or_404, redirect, reverse
from django.core.files.base import ContentFile
from django.contrib import messages
from django.utils.translation import gettext as _
from core.models import AdministrativeRequest
from core.forms import AdministrativeRequestForm

@login_required
def administrative_request_list(request):
    user = request.user
    query = request.GET.get('q', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    name = request.GET.get('name', '')

    # Start with all Administrative Requests (optionally use select_related to improve queries)
    items = AdministrativeRequest.objects.all().select_related('created_by')

    # Permission handling:
    # Only users in roles HR, Admin, or Supervisors see all requests.
    # Others see only their own requests.
    if not user.roles.filter(name__in=['HR', 'Admin', 'Supervisors']).exists():
        items = items.filter(created_by=user)

    # Basic filtering conditions.
    if query:
        items = items.filter(
            Q(admin_request_nu__icontains=query) |
            Q(national_id__icontains=query) |
            Q(name__icontains=query) |
            Q(department__icontains=query)
        )
    if date_from:
        items = items.filter(date__gte=date_from)
    if date_to:
        items = items.filter(date__lte=date_to)
    if name:
        items = items.filter(name__icontains=name)

    items = items.order_by('-date')

    context = {
        'title': "Administrative Requests",
        'search_url': 'administrative_request_list',
        'create_url': 'administrative_request_create',
        'items': items,
        'query': query,
        'date_from': date_from,
        'date_to': date_to,
        'name': name,
    }
    return render(request, 'core/administrative_request_list.html', context)

@login_required
def administrative_request_create(request):
    # Workers should not be allowed to create administrative requests.
    if request.user.roles.filter(name="Worker").exists():
        return HttpResponseForbidden("Workers cannot create administrative requests.")

    # Pass the current user to the form.
    if request.method == "POST":
        form = AdministrativeRequestForm(request.POST, request.FILES, user=request.user)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.created_by = request.user

            # Handle signature conversion if provided.
            signature_data = request.POST.get("signature_data", "")
            if signature_data and signature_data.startswith("data:image"):
                fmt, imgstr = signature_data.split(";base64,")
                ext = fmt.split("/")[-1]
                # Save signature (ensure object has a pk if needed, so call save() first if required)
                obj.save()  # Save first to generate PK if needed.
                obj.signature.save(
                    f"employee_signature_{obj.pk}.{ext}",
                    ContentFile(base64.b64decode(imgstr)),
                    save=True
                )
            else:
                obj.save()

            messages.success(request, "Administrative Request created successfully!")
            return redirect("administrative_request_list")
        else:
            messages.error(request, "Error creating Administrative Request. Please check the form.")
    else:
        form = AdministrativeRequestForm(user=request.user)

    return render(request, "core/administrative_request_form.html", {"form": form, "title": "Create Administrative Request"})

@login_required
def administrative_request_update(request, pk):
    instance = get_object_or_404(AdministrativeRequest, pk=pk)
    # Only users with roles HR, Admin, or Supervisors may update any record.
    # Others may update only their own.
    if not request.user.roles.filter(name__in=['HR', 'Admin', 'Supervisors']).exists():
        if instance.created_by != request.user:
            return HttpResponseForbidden("You do not have permission to edit this request.")

    if request.method == "POST":
        form = AdministrativeRequestForm(request.POST, request.FILES, instance=instance, user=request.user)
        if form.is_valid():
            obj = form.save(commit=False)
            # Process signature data if provided.
            signature_data = request.POST.get("signature_data", "")
            if signature_data and signature_data.startswith("data:image"):
                fmt, imgstr = signature_data.split(";base64,")
                ext = fmt.split("/")[-1]
                obj.signature.save(
                    f"employee_signature_{obj.pk}.{ext}",
                    ContentFile(base64.b64decode(imgstr)),
                    save=True
                )
            obj.save()
            messages.success(request, "Administrative Request updated successfully!")
            return redirect("administrative_request_list")
        else:
            messages.error(request, "Error updating Administrative Request. Please check the form.")
    else:
        form = AdministrativeRequestForm(instance=instance, user=request.user)

    return render(request, "core/administrative_request_form.html", {"form": form, "title": "Edit Administrative Request"})

@login_required
def administrative_request_delete(request, pk):
    instance = get_object_or_404(AdministrativeRequest, pk=pk)
    if request.method == 'POST':
        instance.delete()
        messages.success(request, 'Administrative Request deleted successfully!')
        return redirect('administrative_request_list')
    return render(request, 'core/administrative_request_confirm_delete.html', {'item': instance})

# Optional: Manager and GM approvals using JSON responses.
@login_required
def update_manager_approval(request):
    if request.method == "POST":
        data = json.loads(request.body)
        try:
            request_obj = AdministrativeRequest.objects.get(id=data['id'])
            request_obj.manager_approval_status = data['status']
            request_obj.save()
            return JsonResponse({"success": True, "status": request_obj.manager_approval_status})
        except AdministrativeRequest.DoesNotExist:
            return JsonResponse({"success": False, "error": "Request not found"})
    return JsonResponse({"success": False, "error": "Invalid request"})

@login_required
def update_gm_approval(request):
    if request.method == "POST":
        data = json.loads(request.body)
        try:
            request_obj = AdministrativeRequest.objects.get(id=data['id'])
            request_obj.gm_approval_status = data['status']
            request_obj.save()
            return JsonResponse({"success": True, "status": request_obj.gm_approval_status})
        except AdministrativeRequest.DoesNotExist:
            return JsonResponse({"success": False, "error": "Request not found"})
    return JsonResponse({"success": False, "error": "Invalid request"})

# Technical Office Storage Management
@login_required
def technical_office_storage_list(request):
    items = TechnicalOfficeStorage.objects.all()
    context = {
        'title': "Technical Office Storage",
        'search_url': 'technical_office_storage_list',
        'create_url': 'technical_office_storage_create',
        'table_headers': [
            "No.", "File Type", "File Name", "Description", "Location", "Date Applied", "Date Receiving Apply",
            "Code", "Notes for Approval or Rejection", "Attachment", "Actions"
        ],
        'table_fields': [
            'no', 'file_type', 'file_name', 'description', 'location', 'date_applied', 'date_receiving_apply',
            'code', 'notes_for_approval_or_rejection', 'attachment'
        ],
        'items': items,
    }
    return render(request, 'core/technical_office_storage_list.html', context)

@login_required
def technical_office_storage_create(request):
    if request.method == 'POST':
        form = TechnicalOfficeStorageForm(request.POST, request.FILES)
        if form.is_valid():
            item = form.save(commit=False)
            item.created_by = request.user
            item.save()
            messages.success(request, 'Technical office storage item added successfully!')
            return redirect('technical_office_storage_list')
        else:
            messages.error(request, 'Error adding item.')
    else:
        form = TechnicalOfficeStorageForm()
    return render(request, 'core/technical_office_storage_form.html', {'form': form, 'title': 'Add New Technical Office Storage Item'})

@login_required
def technical_office_storage_update(request, pk):
    item = get_object_or_404(TechnicalOfficeStorage, pk=pk)
    if request.method == 'POST':
        form = TechnicalOfficeStorageForm(request.POST, request.FILES, instance=item)
        if form.is_valid():
            form.save()
            messages.success(request, 'Technical office storage item updated successfully!')
            return redirect('technical_office_storage_list')
        else:
            messages.error(request, 'Error updating item.')
    else:
        form = TechnicalOfficeStorageForm(instance=item)
    return render(request, 'core/technical_office_storage_form.html', {'form': form, 'title': 'Edit Technical Office Storage Item'})

@login_required
def technical_office_storage_delete(request, pk):
    item = get_object_or_404(TechnicalOfficeStorage, pk=pk)
    if request.method == 'POST':
        item.delete()
        messages.success(request, 'Technical office storage item deleted successfully!')
        return redirect('technical_office_storage_list')
    return render(request, 'core/technical_office_storage_confirm_delete.html', {'item': item})


def save_signature(signature_data, filename):
    """Convert Base64 signature data to an image and save it."""
    if signature_data and signature_data.startswith("data:image/png;base64"):
        format, imgstr = signature_data.split(";base64,") 
        return ContentFile(base64.b64decode(imgstr), name=filename)
    return None

from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpResponseForbidden
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.core.files.base import ContentFile
import base64

from core.models import ITWarehouse, Department, RequestType
from core.forms import ITWarehouseForm

@login_required
def it_warehouse_list(request):
    user = request.user
    query    = request.GET.get('q', '')
    date_from = request.GET.get('date_from', '')
    date_to   = request.GET.get('date_to', '')
    item_type = request.GET.get('item_type', '')

    items = ITWarehouse.objects.all().order_by('-item_no')

    # Basic filtering
    if query:
        items = items.filter(
            Q(item_no__icontains=query) |
            Q(item_model_name__icontains=query) |
            Q(description__icontains=query) |
            Q(specifications__icontains=query)
        )
    if date_from and date_to:
        items = items.filter(date_given__range=[date_from, date_to])
    if item_type:
        items = items.filter(item_type__icontains=item_type)

    # Role-based filtering:
    # Full access for Admins and Managers.
    if user.is_superuser or user.roles.filter(name__in=['Admin', 'Manager']).exists():
        pass
    # Engineers, DCs, and Supervisors can view only items they created or that are assigned to them.
    elif user.roles.filter(name__in=['Engineer', 'DCs', 'Supervisors']).exists():
        items = items.filter(Q(created_by=user) | Q(item_with=user))
    # Workers (and Employees) can only view items assigned to them.
    elif user.roles.filter(name__in=['Worker', 'Employee']).exists():
        items = items.filter(item_with=user)
    else:
        return HttpResponseForbidden("You do not have permission to view IT warehouse items.")

    context = {
        'items': items,
        'query': query,
        'date_from': date_from,
        'date_to': date_to,
        'item_type': item_type,
        'departments': Department.objects.all(),
        'request_types': RequestType.objects.all(),
    }
    return render(request, 'core/it_warehouse_list.html', context)


@login_required
def it_warehouse_detail(request, pk):
    item = get_object_or_404(ITWarehouse, pk=pk)
    user = request.user

    # Full access for Admins and Managers.
    if user.is_superuser or user.roles.filter(name__in=['Admin', 'Manager']).exists():
        pass
    # Engineers, DCs, and Supervisors may view only if the item is assigned to them.
    elif user.roles.filter(name__in=['Engineer', 'DCs', 'Supervisors']).exists():
        if item.item_with != user:
            return HttpResponseForbidden("You do not have permission to view this item.")
    # Workers (and Employees) can view only if assigned to them.
    elif user.roles.filter(name__in=['Worker', 'Employee']).exists():
        if item.item_with != user:
            return HttpResponseForbidden("You do not have permission to view this item.")
    else:
        return HttpResponseForbidden("You do not have permission to view this item.")

    return render(request, 'core/it_warehouse_view.html', {'item': item})


@login_required
def it_warehouse_create(request):
    # Only Admins and Managers can create IT warehouse items.
    if not (request.user.is_superuser or request.user.roles.filter(name__in=['Admin', 'Manager']).exists()):
        return HttpResponseForbidden("You do not have permission to create IT warehouse items.")

    if request.method == 'POST':
        form = ITWarehouseForm(request.POST, request.FILES)
        if form.is_valid():
            item = form.save(commit=False)
            item.created_by = request.user
            item.save()

            # Save Holder Signature if provided.
            signature_holder_data = request.POST.get("signature_holder", "")
            if signature_holder_data:
                item.signature_holder.save(
                    f"signature_holder_{item.pk}.png",
                    save_signature(signature_holder_data, f"signature_holder_{item.pk}.png"),
                    save=True
                )

            # Save Department Manager Signature if provided.
            signature_manager_data = request.POST.get("signature_department_manager", "")
            if signature_manager_data:
                item.signature_department_manager.save(
                    f"signature_manager_{item.pk}.png",
                    save_signature(signature_manager_data, f"signature_manager_{item.pk}.png"),
                    save=True
                )

            item.save()
            messages.success(request, 'IT warehouse item added successfully!')
            return redirect('it_warehouse_list')
        else:
            messages.error(request, 'Error adding IT warehouse item. Please check the form.')
    else:
        form = ITWarehouseForm()
    
    return render(request, 'core/it_warehouse_form.html', {'form': form, 'title': 'Add New IT Warehouse Item'})


@login_required
def it_warehouse_update(request, pk):
    item = get_object_or_404(ITWarehouse, pk=pk)
    user = request.user

    # Only Admins and Managers have full update rights.
    if not (user.is_superuser or user.roles.filter(name__in=['Admin', 'Manager']).exists()):
        return HttpResponseForbidden("You do not have permission to update IT warehouse items.")

    if request.method == 'POST':
        form = ITWarehouseForm(request.POST, request.FILES, instance=item)
        if form.is_valid():
            item = form.save(commit=False)

            # Optionally, if an employee is allowed to sign only once:
            if user == item.item_with and item.signature_holder:
                messages.error(request, "You have already signed. Further edits are not allowed.")
                return redirect('it_warehouse_list')
            else:
                signature_holder_data = request.POST.get("signature_holder", "")
                if signature_holder_data:
                    item.signature_holder.save(
                        f"signature_holder_{item.pk}.png",
                        save_signature(signature_holder_data, f"signature_holder_{item.pk}.png"),
                        save=True
                    )

            # Full permission users (Admin/Manager) can update the manager signature.
            signature_manager_data = request.POST.get("signature_department_manager", "")
            if signature_manager_data:
                item.signature_department_manager.save(
                    f"signature_manager_{item.pk}.png",
                    save_signature(signature_manager_data, f"signature_manager_{item.pk}.png"),
                    save=True
                )

            item.save()
            messages.success(request, 'IT warehouse item updated successfully!')
            return redirect('it_warehouse_list')
        else:
            messages.error(request, 'Error updating IT warehouse item.')
    else:
        form = ITWarehouseForm(instance=item)

    return render(request, 'core/it_warehouse_form.html', {'form': form, 'title': 'Edit IT Warehouse Item'})


@login_required
def it_warehouse_delete(request, pk):
    item = get_object_or_404(ITWarehouse, pk=pk)
    # Only Admins and Managers can delete items.
    if not (request.user.is_superuser or request.user.roles.filter(name__in=['Admin', 'Manager']).exists()):
        return HttpResponseForbidden("You do not have permission to delete IT warehouse items.")

    if request.method == 'POST':
        item.delete()
        messages.success(request, 'IT warehouse item deleted successfully!')
        return redirect('it_warehouse_list')
    return render(request, 'core/it_warehouse_confirm_delete.html', {'item': item})

# IT Request Management
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpResponseForbidden
from django.shortcuts import render, get_object_or_404, redirect, reverse
from django.contrib import messages
from django.core.files.base import ContentFile
import base64

from core.models import ITRequest, Department, RequestType, Signature, CustomUser
from core.forms import ITRequestForm

import base64
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpResponseForbidden
from django.shortcuts import render, get_object_or_404, redirect, reverse
from django.core.files.base import ContentFile
from django.contrib import messages
from django.utils.translation import gettext as _
from core.models import ITRequest, Department, RequestType, Signature, CustomUser
from core.forms import ITRequestForm

@login_required
def it_request_list(request):
    user = request.user
    query      = request.GET.get('q', '')
    date_from  = request.GET.get('date_from', '')
    date_to    = request.GET.get('date_to', '')
    title      = request.GET.get('title', '')

    # Start with all IT Requests ordered by descending request number.
    items = ITRequest.objects.all().order_by('-request_no')

    # Basic filtering.
    if query:
        items = items.filter(
            Q(request_no__icontains=query) |
            Q(title__icontains=query) |
            Q(description__icontains=query) |
            Q(it_request_type__icontains=query) |
            Q(name__icontains=query)
        )
    if date_from and date_to:
        items = items.filter(date_applied__range=[date_from, date_to])
    if title:
        items = items.filter(title__icontains=title)

    # Role-based filtering:
    # Privileged users (superuser, Admin, Manager, Engineer) see all IT Requests.
    if user.is_superuser or user.roles.filter(name__in=['Admin', 'Manager', 'Engineer']).exists():
        pass  # full access
    else:
        # All other users see only IT Requests where they appear in any key field.
        items = items.filter(
            Q(created_by=user) | Q(applied_for=user) | Q(assigned_to=user)
        )

    context = {
        'items': items,
        'query': query,
        'date_from': date_from,
        'date_to': date_to,
        'title': title,
        'departments': Department.objects.all(),
        'request_types': RequestType.objects.all(),
        'table_headers': [
            "Request No", "Department", "Request Type", "Title", "Description",
            "Created By", "Applied For", "Assigned To", "Date & Time", "Status",
            "Notes", "Attachment", "Signature", "Actions"
        ],
        'table_fields': [
            'id', 'department.name', 'request_type.name', 'title', 'description',
            'get_created_by_full_name', 'get_applied_for_full_name', 'get_assigned_to_full_name',
            'date_created', 'get_status_display', 'notes', 'attachment', 'signature'
        ],
        'search_url': 'it_request_list',
        'create_url': 'it_request_create',
        'detail_url': 'it_request_detail',
        'update_url': 'it_request_update',
        'delete_url': 'it_request_delete'
    }
    return render(request, 'core/it_request_list.html', context)

@login_required
def it_request_create(request):
    # Allow creation for privileged roles: Admin, Manager, Engineer, Supervisor, and DCs.
    if not (request.user.is_superuser or 
            request.user.roles.filter(name__in=['Admin', 'Manager', 'Engineer', 'Supervisor', 'DCs']).exists()):
        return HttpResponseForbidden("You do not have permission to create IT requests.")

    if request.method == 'POST':
        form = ITRequestForm(request.POST, request.FILES)
        if form.is_valid():
            it_request = form.save(commit=False)
            it_request.created_by = request.user
            # Use provided applied_for if checkbox is checked; otherwise, default to current user.
            if request.POST.get('apply_for_others') == "on" and form.cleaned_data.get('applied_for'):
                it_request.applied_for = form.cleaned_data.get('applied_for')
            else:
                it_request.applied_for = request.user
            it_request.save()

            # Handle signature if provided.
            signature_data_url = request.POST.get('signature')
            if signature_data_url:
                fmt, imgstr = signature_data_url.split(';base64,')
                ext = fmt.split('/')[-1]
                signature = Signature(
                    it_request=it_request,
                    image=ContentFile(base64.b64decode(imgstr), name=f'signature_{it_request.id}.{ext}'),
                    name=request.user.get_full_name()
                )
                signature.save()

            messages.success(request, 'IT Request added successfully!')
            return redirect('it_request_list')
        else:
            messages.error(request, 'Error creating IT request. Please check the form.')
    else:
        form = ITRequestForm()
    return render(request, 'core/it_request_form.html', {'form': form, 'title': 'Add IT Request'})

@login_required
def it_request_update(request, pk):
    it_request = get_object_or_404(ITRequest, pk=pk)
    user = request.user

    # Allow update if the user is superuser, Admin/Manager, or the creator.
    if not (user.is_superuser or user.roles.filter(name__in=['Admin', 'Manager']).exists() or user == it_request.created_by):
        return HttpResponseForbidden("You do not have permission to update this IT request.")

    if request.method == 'POST':
        form = ITRequestForm(request.POST, request.FILES, instance=it_request)
        if form.is_valid():
            it_request = form.save(commit=False)
            if request.POST.get('apply_for_others') == "on" and form.cleaned_data.get('applied_for'):
                it_request.applied_for = form.cleaned_data.get('applied_for')
            else:
                it_request.applied_for = request.user
            it_request.save()

            # Handle signature if provided.
            signature_data_url = request.POST.get('signature')
            if signature_data_url:
                fmt, imgstr = signature_data_url.split(';base64,')
                ext = fmt.split('/')[-1]
                signature = Signature(
                    it_request=it_request,
                    image=ContentFile(base64.b64decode(imgstr), name=f'signature_{it_request.id}.{ext}'),
                    name=request.user.get_full_name()
                )
                signature.save()

            messages.success(request, 'IT Request updated successfully!')
            return redirect('it_request_detail', pk=it_request.pk)
        else:
            messages.error(request, 'Error updating IT request.')
    else:
        form = ITRequestForm(instance=it_request)
    return render(request, 'core/it_request_form.html', {'form': form, 'title': 'Update IT Request'})

@login_required
def it_request_update_status(request, pk):
    it_request = get_object_or_404(ITRequest, pk=pk)
    user = request.user

    # Allow status update only for superusers or Admin/Manager.
    if not (user.is_superuser or user.roles.filter(name__in=['Admin', 'Manager']).exists()):
        return HttpResponseForbidden("You do not have permission to update IT request status.")

    if request.method == 'POST':
        status = request.POST.get('status')
        notes = request.POST.get('notes')
        if status in dict(ITRequest.STATUS_CHOICES):
            it_request.status = status
            if notes:
                it_request.notes = notes
            it_request.save()
            messages.success(request, f'IT Request status updated to {status}.')
            return redirect('it_request_list')
        else:
            messages.error(request, "Invalid status.")
    return render(request, 'core/it_request_update_status.html', {'it_request': it_request})

@login_required
def it_request_delete(request, pk):
    it_request = get_object_or_404(ITRequest, pk=pk)
    user = request.user

    # Allow deletion only for superusers, the creator, or Admin/Manager.
    if not (user.is_superuser or user == it_request.created_by or user.roles.filter(name__in=['Admin', 'Manager']).exists()):
        return HttpResponseForbidden("You do not have permission to delete this IT request.")

    if request.method == 'POST':
        it_request.delete()
        messages.success(request, 'IT Request deleted successfully!')
        return redirect('it_request_list')
    return render(request, 'core/it_request_confirm_delete.html', {'item': it_request})


# My Possession Management
@login_required
def my_possession_list(request):
    items = MyPossession.objects.filter(user=request.user)
    context = {
        'title': "My Possessions",
        'search_url': 'my_possession_list',
        'create_url': 'my_possession_create',
        'table_headers': [
            "No.", "Item Type", "Quantity", "Date Received", "Date Returned", "Attachment Paper",
            "Attachment Item Condition", "Status", "Signature of Receiving", "Actions"
        ],
        'table_fields': [
            'no', 'item_type', 'quantity', 'date_received', 'date_returned', 'attachment_paper',
            'attachment_item_condition', 'status', 'signature_of_receiving'
        ],
        'items': items,
    }
    return render(request, 'core/my_possession_list.html', context)

@login_required
def my_possession_create(request):
    if request.method == 'POST':
        form = MyPossessionForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'Item added to possession successfully!')
            return redirect('my_possession_list')
    else:
        form = MyPossessionForm()
    return render(request, 'core/my_possession_form.html', {'form': form, 'title': 'Add Possession'})

@login_required
def my_possession_update(request, pk):
    item = get_object_or_404(MyPossession, pk=pk)
    if request.method == 'POST':
        form = MyPossessionForm(request.POST, request.FILES, instance=item)
        if form.is_valid():
            form.save()
            messages.success(request, 'Possession updated successfully!')
            return redirect('my_possession_list')
    else:
        form = MyPossessionForm(instance=item)
    return render(request, 'core/my_possession_form.html', {'form': form, 'title': 'Update Possession'})

@login_required
def my_possession_delete(request, pk):
    item = get_object_or_404(MyPossession, pk=pk)
    if request.method == 'POST':
        item.delete()
        messages.success(request, 'Possession deleted successfully!')
        return redirect('my_possession_list')
    return render(request, 'core/my_possession_confirm_delete.html', {'item': item})

# Contractor Management
@login_required
def contractor_list(request):
    contractors = Contractor.objects.all()
    return render(request, 'core/contractor_list.html', {'contractors': contractors})

@login_required
def contractor_create(request):
    if request.method == 'POST':
        form = ContractorForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'Contractor created successfully!')
            return redirect('contractor_list')
    else:
        form = ContractorForm()
    return render(request, 'core/contractor_form.html', {'form': form})

@login_required
def contractor_update(request, pk):
    contractor = get_object_or_404(Contractor, pk=pk)
    if request.method == 'POST':
        form = ContractorForm(request.POST, request.FILES, instance=contractor)
        if form.is_valid():
            form.save()
            messages.success(request, 'Contractor updated successfully!')
            return redirect('contractor_list')
    else:
        form = ContractorForm(instance=contractor)
    return render(request, 'core/contractor_form.html', {'form': form})

@login_required
def contractor_delete(request, pk):
    contractor = get_object_or_404(Contractor, pk=pk)
    if request.method == 'POST':
        contractor.delete()
        messages.success(request, 'Contractor deleted successfully!')
        return redirect('contractor_list')
    return render(request, 'core/contractor_confirm_delete.html', {'contractor': contractor})

# Company Clearance Management
# core/views.py
import datetime
import base64
from django.shortcuts import render, redirect, get_object_or_404, resolve_url
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.files.base import ContentFile
from .models import CompanyClearance, ClearanceSignature
from .forms import CompanyClearanceForm

@login_required
def company_clearance_list(request):
    clearances = CompanyClearance.objects.all().order_by('-today_date')
    return render(request, 'core/company_clearance_list.html', {'clearances': clearances})


@login_required
def company_clearance_create(request):
    if request.method == 'POST':
        form = CompanyClearanceForm(request.POST, user=request.user)
        if form.is_valid():
            clearance = form.save(commit=False)
            # Auto-populate clearance details from the logged-in user
            clearance.first_name = request.user.first_name
            clearance.last_name = request.user.last_name
            clearance.profession = request.user.profession
            clearance.national_id_or_iqama_no = request.user.national_id
            clearance.department = (request.user.department.name 
                                    if hasattr(request.user, 'department') and request.user.department 
                                    else "Not Assigned")
            clearance.today_date = datetime.date.today()
            clearance.save()
            messages.success(request, 'Company clearance created successfully!')
            return redirect('company_clearance_list')
    else:
        form = CompanyClearanceForm(user=request.user)
    return render(request, 'core/company_clearance_form.html', {'form': form})


@login_required
def update_clearance_status(request, pk):
    """
    Allows only users with the Admin or Supervisors roles to update the clearance status.
    Also, checks if the current user has already signed this clearance.
    """
    clearance = get_object_or_404(CompanyClearance, pk=pk)
    
    # Only allow users with Admin or Supervisors roles to update clearance status.
    if not request.user.roles.filter(name__in=['Admin', 'Supervisors']).exists():
        messages.error(request, "You do not have permission to update clearance status.")
        return redirect('company_clearance_list')
    
    # Check if the current user (manager) has already signed this clearance.
    try:
        ClearanceSignature.objects.get(clearance=clearance, manager=request.user)
        can_sign = False
    except ClearanceSignature.DoesNotExist:
        can_sign = True

    if request.method == 'POST' and can_sign:
        new_status = request.POST.get('status')
        approval_note = request.POST.get('approval_note')
        signature_data = request.POST.get('signature_data')

        if new_status not in ['Approved', 'Rejected']:
            messages.error(request, "Invalid status selected.")
            return redirect('update_clearance_status', pk=pk)

        if not signature_data:
            messages.error(request, "Please provide a signature.")
            return redirect('update_clearance_status', pk=pk)

        try:
            # Expecting a data URL like "data:image/png;base64,...."
            fmt, imgstr = signature_data.split(';base64,')
            ext = fmt.split('/')[-1]
            data = ContentFile(base64.b64decode(imgstr), name=f'signature_{pk}_{request.user.pk}.{ext}')
        except Exception as e:
            messages.error(request, "Error processing the signature. Please try again.")
            return redirect('update_clearance_status', pk=pk)

        # Create a new signature record for this clearance and manager.
        ClearanceSignature.objects.create(
            clearance=clearance,
            manager=request.user,
            signature=data,
            approval_note=approval_note,
            status=new_status
        )

        # If 4 or more signatures exist, lock the clearance as approved.
        if clearance.signatures.count() >= 4:
            clearance.status = 'Approved'
            clearance.is_locked = True
            clearance.save()

        messages.success(request, "Your signature has been saved.")
        return redirect('company_clearance_list')
    
    return render(request, 'core/update_clearance_status.html', {
        'clearance': clearance,
        'can_sign': can_sign,
    })


@login_required
def company_clearance_delete(request, pk):
    """
    Only users with the Admin or Supervisors roles can delete a clearance.
    """
    clearance = get_object_or_404(CompanyClearance, pk=pk)
    
    if not request.user.roles.filter(name__in=['Admin', 'Supervisors']).exists():
        messages.error(request, "You do not have permission to delete this clearance.")
        return redirect('company_clearance_list')
        
    if request.method == 'POST':
        clearance.delete()
        messages.success(request, 'Company clearance deleted successfully!')
        return redirect('company_clearance_list')
    return render(request, 'core/company_clearance_confirm_delete.html', {'clearance': clearance})

# views.py
import os
import base64
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.template.loader import render_to_string
from core.models import CompanyClearance, CustomUser
from weasyprint import HTML

@login_required
def export_company_clearance_pdf(request):
    # Retrieve all CompanyClearance records (adjust ordering/filtering as needed)
    clearances = CompanyClearance.objects.all().order_by('-today_date').prefetch_related('signatures')
    
    # Process signatures for each clearance.
    for clearance in clearances:
        # Assume get_signatures() returns a list of signature objects related to the clearance.
        signatures = clearance.get_signatures()
        clearance.signature_data = []
        
        for sig in signatures:
            if sig.signature and hasattr(sig.signature, 'path'):
                try:
                    if os.path.exists(sig.signature.path):
                        with open(sig.signature.path, 'rb') as img_file:
                            img_data = base64.b64encode(img_file.read()).decode('utf-8')
                            clearance.signature_data.append({
                                'data': f"data:image/png;base64,{img_data}",
                                'manager': sig.manager.get_full_name() if sig.manager else '',
                                'status': sig.status,
                                'date': sig.created_at,
                                'note': sig.approval_note,
                            })
                except Exception as e:
                    print(f"Error processing signature: {e}")
                    continue

    context = {
        'clearances': clearances,
        'base_url': request.build_absolute_uri('/'),
        'MEDIA_URL': request.build_absolute_uri(settings.MEDIA_URL)
    }
    return export_to_pdf(request, 'core/company_clearance_pdf.html', context, 'company_clearance')

def export_to_pdf(request, template_name, context, filename):
    # Add MEDIA_URL to context if needed
    context['MEDIA_URL'] = request.build_absolute_uri(settings.MEDIA_URL)
    html_string = render_to_string(template_name, context)
    print("Rendered HTML for export:\n", html_string)  # Debug output

    html = HTML(string=html_string, base_url=request.build_absolute_uri('/'))
    pdf = html.write_pdf()

    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'inline; filename="{filename}.pdf"'
    return response

# ERP Management
@login_required
def erp_list(request):
    erp_entries = ERPEntry.objects.all()
    return render(request, 'core/erp_list.html', {'erp_entries': erp_entries})

@login_required
def erp_create(request):
    if request.method == 'POST':
        form = ERPPurchaseOrderForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'ERP entry created successfully!')
            return redirect('erp_list')
    else:
        form = ERPPurchaseOrderForm()
    return render(request, 'core/erp_form.html', {'form': form, 'title': 'Add ERP Entry'})

@login_required
def erp_update(request, pk):
    erp_entry = get_object_or_404(ERPEntry, pk=pk)
    if request.method == 'POST':
        form = ERPPurchaseOrderForm(request.POST, request.FILES, instance=erp_entry)
        if form.is_valid():
            form.save()
            messages.success(request, 'ERP entry updated successfully!')
            return redirect('erp_list')
    else:
        form = ERPPurchaseOrderForm(instance=erp_entry)
    return render(request, 'core/erp_form.html', {'form': form, 'title': 'Update ERP Entry'})

@login_required
def erp_delete(request, pk):
    erp_entry = get_object_or_404(ERPEntry, pk=pk)
    if request.method == 'POST':
        erp_entry.delete()
        messages.success(request, 'ERP entry deleted successfully!')
        return redirect('erp_list')
    return render(request, 'core/erp_confirm_delete.html', {'erp_entry': erp_entry})

# Accounting Management
@login_required
def accounting_list(request):
    accounting_entries = AccountingEntry.objects.all()
    return render(request, 'core/accounting_list.html', {'accounting_entries': accounting_entries})

@login_required
def accounting_create(request):
    if request.method == 'POST':
        form = AccountingEntryForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'Accounting entry created successfully!')
            return redirect('accounting_list')
    else:
        form = AccountingEntryForm()
    return render(request, 'core/accounting_form.html', {'form': form, 'title': 'Add Accounting Entry'})

@login_required
def accounting_update(request, pk):
    accounting_entry = get_object_or_404(AccountingEntry, pk=pk)
    if request.method == 'POST':
        form = AccountingEntryForm(request.POST, request.FILES, instance=accounting_entry)
        if form.is_valid():
            form.save()
            messages.success(request, 'Accounting entry updated successfully!')
            return redirect('accounting_list')
    else:
        form = AccountingEntryForm(instance=accounting_entry)
    return render(request, 'core/accounting_form.html', {'form': form, 'title': 'Update Accounting Entry'})

@login_required
def accounting_delete(request, pk):
    accounting_entry = get_object_or_404(AccountingEntry, pk=pk)
    if request.method == 'POST':
        accounting_entry.delete()
        messages.success(request, 'Accounting entry deleted successfully!')
        return redirect('accounting_list')
    return render(request, 'core/accounting_confirm_delete.html', {'accounting_entry': accounting_entry})

# CRM Customer Management
@login_required
def crm_customer_list(request):
    crm_customers = CRMCustomer.objects.all()
    return render(request, 'core/crm_customer_list.html', {'crm_customers': crm_customers})

@login_required
def crm_customer_create(request):
    if request.method == 'POST':
        form = CRMCustomerForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'CRM customer created successfully!')
            return redirect('crm_customer_list')
    else:
        form = CRMCustomerForm()
    return render(request, 'core/crm_customer_form.html', {'form': form})

@login_required
def crm_customer_update(request, pk):
    crm_customer = get_object_or_404(CRMCustomer, pk=pk)
    if request.method == 'POST':
        form = CRMCustomerForm(request.POST, request.FILES, instance=crm_customer)
        if form.is_valid():
            form.save()
            messages.success(request, 'CRM customer updated successfully!')
            return redirect('crm_customer_list')
    else:
        form = CRMCustomerForm(instance=crm_customer)
    return render(request, 'core/crm_customer_form.html', {'form': form})

@login_required
def crm_customer_delete(request, pk):
    crm_customer = get_object_or_404(CRMCustomer, pk=pk)
    if request.method == 'POST':
        crm_customer.delete()
        messages.success(request, 'CRM customer deleted successfully!')
        return redirect('crm_customer_list')
    return render(request, 'core/crm_customer_confirm_delete.html', {'crm_customer': crm_customer})

# CRM Lead Management
@login_required
def crm_lead_list(request):
    crm_leads = CRMLead.objects.all()
    return render(request, 'core/crm_lead_list.html', {'crm_leads': crm_leads})

@login_required
def crm_lead_create(request):
    if request.method == 'POST':
        form = CRMLeadForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'CRM lead created successfully!')
            return redirect('crm_lead_list')
    else:
        form = CRMLeadForm()
    return render(request, 'core/crm_lead_form.html', {'form': form})

@login_required
def crm_lead_update(request, pk):
    crm_lead = get_object_or_404(CRMLead, pk=pk)
    if request.method == 'POST':
        form = CRMLeadForm(request.POST, request.FILES, instance=crm_lead)
        if form.is_valid():
            form.save()
            messages.success(request, 'CRM lead updated successfully!')
            return redirect('crm_lead_list')
    else:
        form = CRMLeadForm(instance=crm_lead)
    return render(request, 'core/crm_lead_form.html', {'form': form})

@login_required
def crm_lead_delete(request, pk):
    crm_lead = get_object_or_404(CRMLead, pk=pk)
    if request.method == 'POST':
        crm_lead.delete()
        messages.success(request, 'CRM lead deleted successfully!')
        return redirect('crm_lead_list')
    return render(request, 'core/crm_lead_confirm_delete.html', {'crm_lead': crm_lead})

# Journal Entry Management
@login_required
def journal_entry_list(request):
    journal_entries = JournalEntry.objects.all()
    return render(request, 'core/journal_entry_list.html', {'journal_entries': journal_entries})

@login_required
def journal_entry_create(request):
    if request.method == 'POST':
        form = JournalEntryForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Journal entry created successfully!')
            return redirect('journal_entry_list')
    else:
        form = JournalEntryForm()
    return render(request, 'core/journal_entry_form.html', {'form': form, 'title': 'Add Journal Entry'})

@login_required
def journal_entry_update(request, pk):
    journal_entry = get_object_or_404(JournalEntry, pk=pk)
    if request.method == 'POST':
        form = JournalEntryForm(request.POST, instance=journal_entry)
        if form.is_valid():
            form.save()
            messages.success(request, 'Journal entry updated successfully!')
            return redirect('journal_entry_list')
    else:
        form = JournalEntryForm(instance=journal_entry)
    return render(request, 'core/journal_entry_form.html', {'form': form, 'title': 'Update Journal Entry'})

@login_required
def journal_entry_delete(request, pk):
    journal_entry = get_object_or_404(JournalEntry, pk=pk)
    if request.method == 'POST':
        journal_entry.delete()
        messages.success(request, 'Journal entry deleted successfully!')
        return redirect('journal_entry_list')
    return render(request, 'core/journal_entry_confirm_delete.html', {'journal_entry': journal_entry})

# Journal Entry Line Management
@login_required
def journal_entry_line_list(request):
    journal_entry_lines = JournalEntryLine.objects.all()
    return render(request, 'core/journal_entry_line_list.html', {'journal_entry_lines': journal_entry_lines})

@login_required
def journal_entry_line_create(request):
    if request.method == 'POST':
        form = JournalEntryLineForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Journal entry line created successfully!')
            return redirect('journal_entry_line_list')
    else:
        form = JournalEntryLineForm()
    return render(request, 'core/journal_entry_line_form.html', {'form': form, 'title': 'Add Journal Entry Line'})

@login_required
def journal_entry_line_update(request, pk):
    journal_entry_line = get_object_or_404(JournalEntryLine, pk=pk)
    if request.method == 'POST':
        form = JournalEntryLineForm(request.POST, instance=journal_entry_line)
        if form.is_valid():
            form.save()
            messages.success(request, 'Journal entry line updated successfully!')
            return redirect('journal_entry_line_list')
    else:
        form = JournalEntryLineForm(instance=journal_entry_line)
    return render(request, 'core/journal_entry_line_form.html', {'form': form, 'title': 'Update Journal Entry Line'})

@login_required
def journal_entry_line_delete(request, pk):
    journal_entry_line = get_object_or_404(JournalEntryLine, pk=pk)
    if request.method == 'POST':
        journal_entry_line.delete()
        messages.success(request, 'Journal entry line deleted successfully!')
        return redirect('journal_entry_line_list')
    return render(request, 'core/journal_entry_line_confirm_delete.html', {'journal_entry_line': journal_entry_line})

# Salary Management
@login_required
def salary_list(request):
    salaries = Salary.objects.all()
    return render(request, 'core/salary_list.html', {'salaries': salaries})

@login_required
def salary_create(request):
    if request.method == 'POST':
        form = SalaryForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Salary entry created successfully!')
            return redirect('salary_list')
    else:
        form = SalaryForm()
    return render(request, 'core/salary_form.html', {'form': form, 'title': 'Add Salary Entry'})

@login_required
def salary_update(request, pk):
    salary = get_object_or_404(Salary, pk=pk)
    if request.method == 'POST':
        form = SalaryForm(request.POST, instance=salary)
        if form.is_valid():
            form.save()
            messages.success(request, 'Salary entry updated successfully!')
            return redirect('salary_list')
    else:
        form = SalaryForm(instance=salary)
    return render(request, 'core/salary_form.html', {'form': form, 'title': 'Update Salary Entry'})

@login_required
def salary_delete(request, pk):
    salary = get_object_or_404(Salary, pk=pk)
    if request.method == 'POST':
        salary.delete()
        messages.success(request, 'Salary entry deleted successfully!')
        return redirect('salary_list')
    return render(request, 'core/salary_confirm_delete.html', {'salary': salary})

# Employee Allowance Management
@login_required
def employee_allowance_list(request):
    allowances = EmployeeAllowance.objects.all()
    return render(request, 'core/employee_allowance_list.html', {'allowances': allowances})

@login_required
def employee_allowance_create(request):
    if request.method == 'POST':
        form = EmployeeAllowanceForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Allowance created successfully!')
            return redirect('employee_allowance_list')
    else:
        form = EmployeeAllowanceForm()
    return render(request, 'core/employee_allowance_form.html', {'form': form, 'title': 'Add Allowance'})

@login_required
def employee_allowance_update(request, pk):
    allowance = get_object_or_404(EmployeeAllowance, pk=pk)
    if request.method == 'POST':
        form = EmployeeAllowanceForm(request.POST, instance=allowance)
        if form.is_valid():
            form.save()
            messages.success(request, 'Allowance updated successfully!')
            return redirect('employee_allowance_list')
    else:
        form = EmployeeAllowanceForm(instance=allowance)
    return render(request, 'core/employee_allowance_form.html', {'form': form, 'title': 'Update Allowance'})

@login_required
def employee_allowance_delete(request, pk):
    allowance = get_object_or_404(EmployeeAllowance, pk=pk)
    if request.method == 'POST':
        allowance.delete()
        messages.success(request, 'Allowance deleted successfully!')
        return redirect('employee_allowance_list')
    return render(request, 'core/employee_allowance_confirm_delete.html', {'allowance': allowance})

# Financial Advance Management
@login_required
def financial_advance_list(request):
    advances = FinancialAdvance.objects.all()
    return render(request, 'core/financial_advance_list.html', {'advances': advances})

@login_required
def financial_advance_create(request):
    if request.method == 'POST':
        form = FinancialAdvanceForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Financial advance created successfully!')
            return redirect('financial_advance_list')
    else:
        form = FinancialAdvanceForm()
    return render(request, 'core/financial_advance_form.html', {'form': form, 'title': 'Add Financial Advance'})

@login_required
def financial_advance_update(request, pk):
    advance = get_object_or_404(FinancialAdvance, pk=pk)
    if request.method == 'POST':
        form = FinancialAdvanceForm(request.POST, instance=advance)
        if form.is_valid():
            form.save()
            messages.success(request, 'Financial advance updated successfully!')
            return redirect('financial_advance_list')
    else:
        form = FinancialAdvanceForm(instance=advance)
    return render(request, 'core/financial_advance_form.html', {'form': form, 'title': 'Update Financial Advance'})

@login_required
def financial_advance_delete(request, pk):
    advance = get_object_or_404(FinancialAdvance, pk=pk)
    if request.method == 'POST':
        advance.delete()
        messages.success(request, 'Financial advance deleted successfully!')
        return redirect('financial_advance_list')
    return render(request, 'core/financial_advance_confirm_delete.html', {'advance': advance})

# End of Service Reward Management
@login_required
def end_of_service_reward_list(request):
    rewards = EndOfServiceReward.objects.all()
    return render(request, 'core/end_of_service_reward_list.html', {'rewards': rewards})

@login_required
def end_of_service_reward_create(request):
    if request.method == 'POST':
        form = EndOfServiceRewardForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'End of service reward created successfully!')
            return redirect('end_of_service_reward_list')
    else:
        form = EndOfServiceRewardForm()
    return render(request, 'core/end_of_service_reward_form.html', {'form': form, 'title': 'Add End of Service Reward'})

@login_required
def end_of_service_reward_update(request, pk):
    reward = get_object_or_404(EndOfServiceReward, pk=pk)
    if request.method == 'POST':
        form = EndOfServiceRewardForm(request.POST, instance=reward)
        if form.is_valid():
            form.save()
            messages.success(request, 'End of service reward updated successfully!')
            return redirect('end_of_service_reward_list')
    else:
        form = EndOfServiceRewardForm(instance=reward)
    return render(request, 'core/end_of_service_reward_form.html', {'form': form, 'title': 'Update End of Service Reward'})

@login_required
def end_of_service_reward_delete(request, pk):
    reward = get_object_or_404(EndOfServiceReward, pk=pk)
    if request.method == 'POST':
        reward.delete()
        messages.success(request, 'End of service reward deleted successfully!')
        return redirect('end_of_service_reward_list')
    return render(request, 'core/end_of_service_reward_confirm_delete.html', {'reward': reward})


@login_required
def export_tickets_to_pdf(request):
    tickets = Ticket.objects.all().prefetch_related('signatures').select_related(
        'department', 
        'request_type', 
        'applied_by', 
        'applied_for', 
        'assigned_to'
    )

    # Process signatures
    for ticket in tickets:
        for signature in ticket.signatures.all():
            if signature.image and hasattr(signature.image, 'path'):
                try:
                    if os.path.exists(signature.image.path):
                        with open(signature.image.path, 'rb') as img_file:
                            img_data = base64.b64encode(img_file.read()).decode('utf-8')
                            signature.image_data = f"data:image/png;base64,{img_data}"
                except Exception as e:
                    print(f"Error processing signature: {e}")
                    signature.image_data = None

    # Context with base URL for media files
    context = {
        'tickets': tickets,
        'base_url': request.build_absolute_uri('/'),
        'MEDIA_URL': request.build_absolute_uri(settings.MEDIA_URL)
    }

    # Render template
    html_string = render_to_string('core/tickets_pdf.html', context)

    # Generate PDF
    html = HTML(
        string=html_string,
        base_url=request.build_absolute_uri('/')
    )
    
    try:
        result = html.write_pdf()
        
        # Create response
        response = HttpResponse(result, content_type='application/pdf')
        response['Content-Disposition'] = 'inline; filename="tickets.pdf"'
        return response
        
    except Exception as e:
        print(f"PDF Generation Error: {str(e)}")
        return HttpResponse("Error generating PDF", status=500)


from .models import AdministrativeRequest

@login_required
def export_admin_requests_to_pdf(request):
    # Retrieve all administrative requests (adjust filtering as needed)
    administrative_requests = AdministrativeRequest.objects.all()
    context = {
        'administrative_requests': administrative_requests,
        'base_url': request.build_absolute_uri('/')  # used to resolve relative URLs in PDF
    }
    return export_to_pdf(request, 'core/administrative_request_pdf.html', context, 'administrative_requests')

def export_to_pdf(request, template_name, context, file_name):
    html_string = render_to_string(template_name, context)
    html = HTML(string=html_string, base_url=request.build_absolute_uri('/'))
    pdf = html.write_pdf()
    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'inline; filename="{file_name}.pdf"'
    return response

@login_required
def export_hr_warehouse_to_pdf(request):
    hr_warehouse_items = HRWarehouse.objects.all()
    context = {'items': hr_warehouse_items}
    return export_to_pdf(request, 'core/hr_warehouse_pdf.html', context, 'hr_warehouse')


@login_required
def export_administrative_requests_to_pdf(request):
    administrative_requests = AdministrativeRequest.objects.all()
    context = {'administrative_requests': administrative_requests}
    return export_to_pdf(request, 'core/administrative_requests_pdf.html', context, 'administrative_requests')


@login_required
def export_technical_office_storage_to_pdf(request):
    technical_office_storage = TechnicalOfficeStorage.objects.all()
    context = {'technical_office_storage': technical_office_storage}
    return export_to_pdf(request, 'core/technical_office_storage_pdf.html', context, 'technical_office_storage')


@login_required
def export_my_possessions_to_pdf(request):
    my_possessions = MyPossession.objects.filter(user=request.user)
    context = {'my_possessions': my_possessions}
    return export_to_pdf(request, 'core/my_possessions_pdf.html', context, 'my_possessions')


@login_required
def export_contractors_to_pdf(request):
    contractors = Contractor.objects.all()
    context = {'contractors': contractors}
    return export_to_pdf(request, 'core/contractors_pdf.html', context, 'contractors')

@login_required
def export_erp_entries_to_pdf(request):
    erp_entries = ERPEntry.objects.all()
    context = {'erp_entries': erp_entries}
    return export_to_pdf(request, 'core/erp_entries_pdf.html', context, 'erp_entries')

@login_required
def export_accounting_entries_to_pdf(request):
    accounting_entries = AccountingEntry.objects.all()
    context = {'accounting_entries': accounting_entries}
    return export_to_pdf(request, 'core/accounting_entries_pdf.html', context, 'accounting_entries')


@login_required
def export_crm_customers_to_pdf(request):
    crm_customers = CRMCustomer.objects.all()
    context = {'crm_customers': crm_customers}
    return export_to_pdf(request, 'core/crm_customers_pdf.html', context, 'crm_customers')


@login_required
def export_crm_leads_to_pdf(request):
    crm_leads = CRMLead.objects.all()
    context = {'crm_leads': crm_leads}
    return export_to_pdf(request, 'core/crm_leads_pdf.html', context, 'crm_leads')


@login_required
def export_journal_entries_to_pdf(request):
    journal_entries = JournalEntry.objects.all()
    context = {'journal_entries': journal_entries}
    return export_to_pdf(request, 'core/journal_entries_pdf.html', context, 'journal_entries')


@login_required
def export_journal_entry_lines_to_pdf(request):
    journal_entry_lines = JournalEntryLine.objects.all()
    context = {'journal_entry_lines': journal_entry_lines}
    return export_to_pdf(request, 'core/journal_entry_lines_pdf.html', context, 'journal_entry_lines')


@login_required
def export_salaries_to_pdf(request):
    salaries = Salary.objects.all()
    context = {'salaries': salaries}
    return export_to_pdf(request, 'core/salaries_pdf.html', context, 'salaries')


@login_required
def export_employee_allowances_to_pdf(request):
    employee_allowances = EmployeeAllowance.objects.all()
    context = {'employee_allowances': employee_allowances}
    return export_to_pdf(request, 'core/employee_allowances_pdf.html', context, 'employee_allowances')


@login_required
def export_financial_advances_to_pdf(request):
    financial_advances = FinancialAdvance.objects.all()
    context = {'financial_advances': financial_advances}
    return export_to_pdf(request, 'core/financial_advances_pdf.html', context, 'financial_advances')



from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.template.loader import render_to_string
from weasyprint import HTML
from .models import FinancialWarehouse  # Adjust this import if needed

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.template.loader import render_to_string
from core.models import FinancialWarehouse
from weasyprint import HTML

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.template.loader import render_to_string
from core.models import FinancialWarehouse
from weasyprint import HTML

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.template.loader import render_to_string
from core.models import FinancialWarehouse
from weasyprint import HTML

@login_required
def export_financial_warehouse_to_pdf(request):
    # Retrieve all FinancialWarehouse records
    items = list(FinancialWarehouse.objects.all())
    print("Exporting Financial Warehouse items count:", len(items))  # Debug output

    context = {
        'items': items,
        'base_url': request.build_absolute_uri('/')  # Needed for resolving static URLs
    }
    
    # Render the template to a string
    html_string = render_to_string('core/financial_warehouse_pdf.html', context)
    print("Rendered HTML for export:\n", html_string)  # Debug output

    # Convert the rendered HTML to PDF using WeasyPrint
    html = HTML(string=html_string, base_url=request.build_absolute_uri('/'))
    pdf = html.write_pdf()

    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="financial_warehouse.pdf"'
    return response


from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.template.loader import render_to_string
from core.models import EmployeeDetails
from weasyprint import HTML

@login_required
def export_employee_details_to_pdf(request):
    employee_details = EmployeeDetails.objects.all()
    print("Employee details count:", employee_details.count())  # Debug output

    # Pass the queryset using the key 'items' to match the template's for-loop
    context = {'items': employee_details}
    
    # Render the template to a string for debugging purposes
    html_string = render_to_string('core/employee_details_pdf.html', context)
    print("Rendered HTML for employee details export:\n", html_string)  # Debug output

    # Convert the rendered HTML to PDF using WeasyPrint
    html = HTML(string=html_string, base_url=request.build_absolute_uri('/'))
    pdf = html.write_pdf()

    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="employee_details.pdf"'
    return response


@login_required
def export_technical_office_storage_to_pdf(request):
    technical_office_storage = TechnicalOfficeStorage.objects.all()
    context = {'technical_office_storage': technical_office_storage}
    return export_to_pdf(request, 'core/technical_office_storage_pdf.html', context, 'technical_office_storage')

@login_required
def export_contractor_to_pdf(request):
    contractors = Contractor.objects.all()
    context = {'contractors': contractors}
    return export_to_pdf(request, 'core/contractors_pdf.html', context, 'contractors')


@login_required
def export_company_clearance_to_pdf(request):
    company_clearance = CompanyClearance.objects.all()
    context = {'company_clearance': company_clearance}
    return export_to_pdf(request, 'core/company_clearance_pdf.html', context, 'company_clearance')


@login_required
def export_my_possession_to_pdf(request):
    my_possession = MyPossession.objects.all()
    context = {'my_possession': my_possession}
    return export_to_pdf(request, 'core/my_possession_pdf.html', context, 'my_possession')


from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import ITRequest

@login_required
def export_it_requests_to_pdf(request):
    it_requests = ITRequest.objects.all()
    context = {
        'it_requests': it_requests,
        'base_url': request.build_absolute_uri('/'),
    }
    return export_to_pdf(request, 'core/it_requests_pdf.html', context, 'it_requests')  # ✅ Correct template name


from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import ITWarehouse  # Ensure correct model import

@login_required
def export_it_warehouse_to_pdf(request):
    it_warehouse_items = ITWarehouse.objects.all()  # ✅ Ensure correct model name
    context = {
        'it_warehouse_items': it_warehouse_items,  # ✅ Matches template variable
        'base_url': request.build_absolute_uri('/'),
    }
    return export_to_pdf(request, 'core/it_warehouse_pdf.html', context, 'it_warehouse')


@login_required
def export_end_of_service_rewards_to_pdf(request):
    end_of_service_rewards = EndOfServiceReward.objects.all()
    context = {'end_of_service_rewards': end_of_service_rewards}
    return export_to_pdf(request, 'core/end_of_service_rewards_pdf.html', context, 'end_of_service_rewards')

@login_required
def export_users_to_pdf(request):
    users = CustomUser.objects.all()
    html_string = render_to_string('core/users_pdf.html', {'users': users})
    html = HTML(string=html_string)
    result = html.write_pdf()

    response = HttpResponse(result, content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename=users.pdf'
    return response


@login_required
def export_roles_to_pdf(request):
    roles = Role.objects.all()
    html_string = render_to_string('core/roles_pdf.html', {'roles': roles})
    html = HTML(string=html_string)
    result = html.write_pdf()

    response = HttpResponse(result, content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename=roles.pdf'
    return response

@login_required
def export_departments_to_pdf(request):
    departments = Department.objects.all()
    html_string = render_to_string('core/departments_pdf.html', {'departments': departments})
    html = HTML(string=html_string)
    result = html.write_pdf()

    response = HttpResponse(result, content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename=departments.pdf'
    return response

@login_required
def export_request_types_to_pdf(request):
    request_types = RequestType.objects.all()
    html_string = render_to_string('core/request_types_pdf.html', {'request_types': request_types})
    html = HTML(string=html_string)
    result = html.write_pdf()

    response = HttpResponse(result, content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename=request_types.pdf'
    return response


@login_required
def export_positions_to_pdf(request):
    positions = Position.objects.all()
    html_string = render_to_string('core/positions_pdf.html', {'positions': positions})
    html = HTML(string=html_string)
    result = html.write_pdf()

    response = HttpResponse(result, content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename=positions.pdf'
    return response


@login_required
def export_company_settings_to_pdf(request):
    company_settings = CompanySettings.objects.all()
    html_string = render_to_string('core/company_settings_pdf.html', {'company_settings': company_settings})
    html = HTML(string=html_string)
    result = html.write_pdf()

    response = HttpResponse(result, content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename=company_settings.pdf'
    return response

@login_required
def ticket_search_view(request):
    search_query = request.GET.get('search', '')
    tickets = Ticket.objects.filter(
        Q(title__icontains=search_query) |
        Q(description__icontains=search_query)
    )
    return render(request, 'core/ticket_list.html', {'tickets': tickets})

# Purchase Management
@login_required
def purchase_order_list(request):
    purchase_orders = ERPPurchaseOrder.objects.all()
    context = {
        'title': "Purchase Orders",
        'search_url': 'purchase_order_list',
        'create_url': 'purchase_order_create',
        'table_headers': [
            "Order No.", "Supplier", "Order Date", "Delivery Date", "Total Amount", "Status", "Actions"
        ],
        'table_fields': [
            'order_no', 'supplier', 'order_date', 'delivery_date', 'total_amount', 'status'
        ],
        'items': purchase_orders,
    }
    return render(request, 'core/purchase_order_list.html', context)

@login_required
def purchase_order_create(request):
    if request.method == 'POST':
        form = ERPPurchaseOrderForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'Purchase order created successfully!')
            return redirect('purchase_order_list')
    else:
        form = ERPPurchaseOrderForm()
    return render(request, 'core/purchase_order_form.html', {'form': form, 'title': 'Create Purchase Order'})

@login_required
def purchase_order_update(request, pk):
    purchase_order = get_object_or_404(ERPPurchaseOrder, pk=pk)
    if request.method == 'POST':
        form = ERPPurchaseOrderForm(request.POST, request.FILES, instance=purchase_order)
        if form.is_valid():
            form.save()
            messages.success(request, 'Purchase order updated successfully!')
            return redirect('purchase_order_list')
    else:
        form = ERPPurchaseOrderForm(instance=purchase_order)
    return render(request, 'core/purchase_order_form.html', {'form': form, 'title': 'Update Purchase Order'})

@login_required
def purchase_order_delete(request, pk):
    purchase_order = get_object_or_404(ERPPurchaseOrder, pk=pk)
    if request.method == 'POST':
        purchase_order.delete()
        messages.success(request, 'Purchase order deleted successfully!')
        return redirect('purchase_order_list')
    return render(request, 'core/purchase_order_confirm_delete.html', {'purchase_order': purchase_order})

# Sales Management
@login_required
def sales_invoice_list(request):
    sales_invoices = ERPInvoice.objects.all()
    context = {
        'title': "Sales Invoices",
        'search_url': 'sales_invoice_list',
        'create_url': 'sales_invoice_create',
        'table_headers': [
            "Invoice No.", "Customer", "Invoice Date", "Total Amount", "Status", "Actions"
        ],
        'table_fields': [
            'invoice_no', 'customer', 'invoice_date', 'total_amount', 'status'
        ],
        'items': sales_invoices,
    }
    return render(request, 'core/sales_invoice_list.html', context)

@login_required
def sales_invoice_create(request):
    if request.method == 'POST':
        form = ERPInvoiceForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'Sales invoice created successfully!')
            return redirect('sales_invoice_list')
    else:
        form = ERPInvoiceForm()
    return render(request, 'core/sales_invoice_form.html', {'form': form, 'title': 'Create Sales Invoice'})

@login_required
def sales_invoice_update(request, pk):
    sales_invoice = get_object_or_404(ERPInvoice, pk=pk)
    if request.method == 'POST':
        form = ERPInvoiceForm(request.POST, request.FILES, instance=sales_invoice)
        if form.is_valid():
            form.save()
            messages.success(request, 'Sales invoice updated successfully!')
            return redirect('sales_invoice_list')
    else:
        form = ERPInvoiceForm(instance=sales_invoice)
    return render(request, 'core/sales_invoice_form.html', {'form': form, 'title': 'Update Sales Invoice'})

@login_required
def sales_invoice_delete(request, pk):
    sales_invoice = get_object_or_404(ERPInvoice, pk=pk)
    if request.method == 'POST':
        sales_invoice.delete()
        messages.success(request, 'Sales invoice deleted successfully!')
        return redirect('sales_invoice_list')
    return render(request, 'core/sales_invoice_confirm_delete.html', {'sales_invoice': sales_invoice})

# Notification Management
def send_notification(user, message):
    # Implement your notification sending logic here
    pass

def check_expiring_items():
    # Implement your logic to check for expiring items here
    pass

@login_required
def notifications(request):
    # Replace with actual logic to fetch notifications
    notifications = [
        {'message': _('New ticket created'), 'url': '#'},
        {'message': _('Ticket assigned to you'), 'url': '#'},
        {'message': _('Ticket status updated'), 'url': '#'}
    ]
    return JsonResponse({'notifications': notifications})

@login_required
def financial_warehouse_request_list(request):
    items = FinancialWarehouseRequest.objects.all()
    context = {
        'title': "Financial Warehouse Requests",
        'search_url': 'financial_warehouse_request_list',
        'create_url': 'financial_warehouse_request_create',
        'table_headers': [
            "Request No.", "Item Name", "Quantity", "Date Requested", "Requested By", "Status", "Actions"
        ],
        'table_fields': [
            'request_no', 'item_name', 'quantity', 'date_requested', 'requested_by', 'status'
        ],
        'items': items,
    }
    return render(request, 'core/financial_warehouse_request_list.html', context)

# Company Clearance Management
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.utils.translation import gettext as _
from django.http import HttpResponse
from django.template.loader import render_to_string
from weasyprint import HTML
from .models import StartWorkPermit
from .forms import StartWorkPermitForm

from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render, get_object_or_404, redirect
from .models import StartWorkPermit
from django.contrib import messages

from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from .models import StartWorkPermit

# Check if the user is admin or manager
def is_admin_or_manager(user):
    return user.is_staff or user.is_superuser

import base64
from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import get_object_or_404, redirect, render, resolve_url
from django.contrib import messages
from django.utils.translation import gettext as _
from .models import StartWorkPermit
from .forms import StartWorkPermitForm, StartWorkPermitStatusForm

# Helper function to check if a user has high-level privileges
def is_admin_or_supervisor(user):
    return user.roles.filter(name__in=['Admin', 'Supervisors']).exists() or user.is_staff or user.is_superuser

# List view: display all work permits (you can add further filtering if needed)
@login_required
def start_work_permit_list(request):
    permits = StartWorkPermit.objects.all().order_by('-created_at')  # Order by newest first
    return render(request, 'core/start_work_permit_list.html', {'permits': permits})


# Update status view: only Admins/Supervisors (or staff/superusers) can update status
@login_required
@user_passes_test(is_admin_or_supervisor, login_url='/forbidden/')
def update_work_permit_status(request, pk):
    permit = get_object_or_404(StartWorkPermit, pk=pk)
    new_status = request.POST.get('status')

    if new_status in ['Approved', 'Rejected']:
        permit.status = new_status
        permit.approved_by = request.user  # Track the approving manager
        permit.save()
        messages.success(request, _(f"Work permit #{permit.id} updated to {new_status}."))
    else:
        messages.error(request, _("Invalid status change."))

    return redirect('start_work_permit_list')


# Create view: all employees can create a work permit; form auto-fills profession if applicable
@login_required
def start_work_permit_create(request):
    if request.method == 'POST':
        form = StartWorkPermitForm(request.POST, request=request)  # Pass request for auto-fill
        if form.is_valid():
            permit = form.save(commit=False)
            permit.employee = request.user  # Assign the logged-in user
            permit.save()
            messages.success(request, _('Work permit added successfully!'))
            return redirect(resolve_url('start_work_permit_list'))
        else:
            messages.error(request, _('Error adding work permit. Please check the form.'))
    else:
        form = StartWorkPermitForm(request=request)

    context = {
        'form': form,
        'title': _('Create Work Permit'),
        'user_details': {
            'first_name': request.user.first_name,
            'last_name': request.user.last_name,
            'id': request.user.id,
            'profession': request.user.profession if hasattr(request.user, 'profession') and request.user.profession else _('Not Assigned')
        }
    }
    return render(request, 'core/start_work_permit_form.html', context)


# Update view: only users with high-level privileges may update a work permit
@login_required
def start_work_permit_update(request, pk):
    permit = get_object_or_404(StartWorkPermit, pk=pk)

    if not is_admin_or_supervisor(request.user):
        messages.error(request, _('You do not have permission to update this work permit.'))
        return redirect('start_work_permit_list')

    if request.method == 'POST':
        form = StartWorkPermitForm(request.POST, instance=permit)
        if form.is_valid():
            form.save()
            messages.success(request, _('Work permit updated successfully!'))
            return redirect('start_work_permit_list')
        else:
            messages.error(request, _('Error updating work permit.'))
    else:
        form = StartWorkPermitForm(instance=permit)

    context = {
        'form': form,
        'title': _('Update Work Permit Status'),
    }
    return render(request, 'core/start_work_permit_form.html', context)


# Update status view (alternative): using a dedicated form for status update
@login_required
@user_passes_test(is_admin_or_supervisor, login_url='/forbidden/')
def start_work_permit_update_status(request, pk):
    permit = get_object_or_404(StartWorkPermit, pk=pk)

    if request.method == "POST":
        form = StartWorkPermitStatusForm(request.POST, instance=permit)
        if form.is_valid():
            form.save()
            messages.success(request, _("Work permit status updated successfully!"))
            return redirect('start_work_permit_list')
        else:
            messages.error(request, _("Error updating status."))
    else:
        form = StartWorkPermitStatusForm(instance=permit)

    return render(request, "core/start_work_permit_update_status.html", {"form": form, "permit": permit})


# Delete view: only high-level users can delete work permits
@login_required
@user_passes_test(is_admin_or_supervisor, login_url='/forbidden/')
def start_work_permit_delete(request, pk):
    permit = get_object_or_404(StartWorkPermit, pk=pk)

    if request.method == "POST":
        permit.delete()
        messages.success(request, _("Work permit deleted successfully!"))
        return redirect('start_work_permit_list')

    return render(request, "core/start_work_permit_confirm_delete.html", {"permit": permit})


@login_required
def export_work_permits_to_pdf(request):
    permits = StartWorkPermit.objects.filter(employee=request.user)
    html = render_to_string('core/start_work_permit_pdf.html', {'permits': permits})
    
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'filename="work_permits.pdf"'
    
    weasyprint.HTML(string=html).write_pdf(response)
    return response

# Health and Safety Management
@login_required
def health_safety_list(request):
    records = HealthSafety.objects.all()
    context = {
        'records': records,
        'title': 'Health and Safety Records',
        'table_headers': ['Record ID', 'Title', 'Description', 'Date', 'Actions'],
        'table_fields': ['id', 'title', 'description', 'date'],
    }
    return render(request, 'core/health_safety_list.html', context)


@login_required
def health_safety_create(request):
    if request.method == 'POST':
        form = HealthSafetyForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, _('Health and Safety record added successfully!'))
            return redirect('health_safety_list')
        else:
            messages.error(request, _('Error adding health and safety record.'))
    else:
        form = HealthSafetyForm()
    return render(request, 'core/health_safety_form.html', {'form': form, 'title': _('Add Health and Safety Record')})


@login_required
def health_safety_update(request, pk):
    record = get_object_or_404(HealthSafety, pk=pk)
    if request.method == 'POST':
        form = HealthSafetyForm(request.POST, instance=record)
        if form.is_valid():
            form.save()
            messages.success(request, _('Health and Safety record updated successfully!'))
            return redirect('health_safety_list')
        else:
            messages.error(request, _('Error updating health and safety record.'))
    else:
        form = HealthSafetyForm(instance=record)
    return render(request, 'core/health_safety_form.html', {'form': form, 'title': _('Edit Health and Safety Record')})


@login_required
def health_safety_delete(request, pk):
    record = get_object_or_404(HealthSafety, pk=pk)
    if request.method == 'POST':
        record.delete()
        messages.success(request, _('Health and Safety record deleted successfully!'))
        return redirect('health_safety_list')
    return render(request, 'core/health_safety_confirm_delete.html', {'record': record})


# Workshop Management
@login_required
def workshop_list(request):
    workshops = Workshop.objects.all()
    context = {
        'workshops': workshops,
        'title': 'Workshops',
        'table_headers': ['Workshop ID', 'Name', 'Date', 'Description', 'Actions'],
        'table_fields': ['id', 'name', 'date', 'description'],
    }
    return render(request, 'core/workshop_list.html', context)


@login_required
def workshop_create(request):
    if request.method == 'POST':
        form = WorkshopForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, _('Workshop added successfully!'))
            return redirect('workshop_list')
        else:
            messages.error(request, _('Error adding workshop.'))
    else:
        form = WorkshopForm()
    return render(request, 'core/workshop_form.html', {'form': form, 'title': _('Add Workshop')})


@login_required
def workshop_update(request, pk):
    workshop = get_object_or_404(Workshop, pk=pk)
    if request.method == 'POST':
        form = WorkshopForm(request.POST, instance=workshop)
        if form.is_valid():
            form.save()
            messages.success(request, _('Workshop updated successfully!'))
            return redirect('workshop_list')
        else:
            messages.error(request, _('Error updating workshop.'))
    else:
        form = WorkshopForm(instance=workshop)
    return render(request, 'core/workshop_form.html', {'form': form, 'title': _('Edit Workshop')})

@login_required
def workshop_delete(request, pk):
    workshop = get_object_or_404(Workshop, pk=pk)
    if request.method == 'POST':
        workshop.delete()
        messages.success(request, _('Workshop deleted successfully!'))
        return redirect('workshop_list')
    return render(request, 'core/workshop_confirm_delete.html', {'workshop': workshop})

# Sales Management
@login_required
def sales_list(request):
    sales = Sale.objects.all()
    context = {
        'sales': sales,
        'title': 'Sales',
        'table_headers': ['Sale ID', 'Item', 'Quantity', 'Price', 'Date', 'Actions'],
        'table_fields': ['id', 'item', 'quantity', 'price', 'date'],
    }
    return render(request, 'core/sales_list.html', context)

@login_required
def sales_create(request):
    if request.method == 'POST':
        form = SaleForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, _('Sale added successfully!'))
            return redirect('sales_list')
        else:
            messages.error(request, _('Error adding sale.'))
    else:
        form = SaleForm()
    return render(request, 'core/sale_form.html', {'form': form, 'title': _('Add Sale')})

@login_required
def sales_update(request, pk):
    sale = get_object_or_404(Sale, pk=pk)
    if request.method == 'POST':
        form = SaleForm(request.POST, instance=sale)
        if form.is_valid():
            form.save()
            messages.success(request, _('Sale updated successfully!'))
            return redirect('sales_list')
        else:
            messages.error(request, _('Error updating sale.'))
    else:
        form = SaleForm(instance=sale)
    return render(request, 'core/sale_form.html', {'form': form, 'title': _('Edit Sale')})

@login_required
def sales_delete(request, pk):
    sale = get_object_or_404(Sale, pk=pk)
    if request.method == 'POST':
        sale.delete()
        messages.success(request, _('Sale deleted successfully!'))
        return redirect('sales_list')
    return render(request, 'core/sale_confirm_delete.html', {'sale': sale})

# Utility Functions
def format_context(queryset, title, table_headers, table_fields):
    return {
        'objects': queryset,
        'title': title,
        'table_headers': table_headers,
        'table_fields': table_fields,
    }


