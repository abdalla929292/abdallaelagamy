from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm
from django.contrib.auth.models import Permission
from .models import (
    CustomUser, Role, Position, Department, RequestType, Ticket, CompanySettings,
    SubRequestType, SubPosition, FinancialWarehouse, HRWarehouse, EmployeeDetails,
    AdministrativeRequest, TechnicalOfficeStorage, ITWarehouse, ITRequest, MyPossession, Contractor, CompanyClearance,
    FinancialWarehouseRequest, Account, JournalEntry, JournalEntryLine, EmployeeAllowance, FinancialAdvance,
    EndOfServiceReward, CRMCustomer, CRMLead, ERPPurchaseOrder, ERPInvoice,
    AccountingEntry, CRMTicket, ERPEntry, Salary
)
from django import forms
from .models import StartWorkPermit, HealthSafety, Workshop
from datetime import timedelta  # Ensure this is at the top of forms.py
from django import forms
from django.contrib.auth.models import User
from .models import AdministrativeRequest


from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password1', 'password2', 'first_name', 
                  'last_name', 'roles', 'position', 'department', 'national_id', 'profession')  # ✅ Added profession

class CustomUserUpdateForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'first_name', 'last_name', 'roles', 
                  'position', 'department', 'national_id', 'profession')  # ✅ Added profession

class CustomUserLoginForm(AuthenticationForm):
    class Meta:
        model = CustomUser
        fields = ('username', 'password')


class PasswordChangeForm(PasswordChangeForm):
    class Meta:
        model = CustomUser
        fields = ('New Password', 'Confirm New password')

from django import forms
from core.models import Role

class RoleForm(forms.ModelForm):
    permissions = forms.ModelMultipleChoiceField(
        queryset=Role._meta.get_field('permissions').remote_field.model.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False,
        help_text="Select permissions for this role."
    )

    class Meta:
        model = Role
        fields = ['name', 'permissions']


class PositionForm(forms.ModelForm):
    class Meta:
        model = Position
        fields = ['name']


class DepartmentForm(forms.ModelForm):
    class Meta:
        model = Department
        fields = ['name']


class TicketForm(forms.ModelForm):
    enable_applied_for = forms.BooleanField(required=False, label='Apply for another user')
    sub_request_type = forms.ModelChoiceField(queryset=SubRequestType.objects.none(), required=False, label='Sub Request Type')

    class Meta:
        model = Ticket
        fields = ['title', 'department', 'description', 'request_type', 'sub_request_type', 'assigned_to', 'applied_for', 'attachment']
        widgets = {
            'signature': forms.ClearableFileInput(attrs={'accept': 'image/*'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['assigned_to'].queryset = CustomUser.objects.all()
        self.fields['applied_for'].queryset = CustomUser.objects.all()
        self.fields['department'].queryset = Department.objects.all()
        if 'request_type' in self.data:
            try:
                request_type_id = int(self.data.get('request_type'))
                self.fields['sub_request_type'].queryset = SubRequestType.objects.filter(main_request_type_id=request_type_id)
            except (ValueError, TypeError):
                pass
        elif self.instance.pk:
            self.fields['sub_request_type'].queryset = self.instance.request_type.sub_request_types.all()

def clean(self):
    cleaned_data = super().clean()
    enable_applied_for = cleaned_data.get("enable_applied_for")
    applied_for = cleaned_data.get("applied_for")

    if enable_applied_for and not applied_for:
        raise forms.ValidationError("You must select a user to apply for.")

    if not enable_applied_for:
        cleaned_data['applied_for'] = self.instance.applied_by if self.instance.pk else self.initial.get('applied_by')

    return cleaned_data


class CompanySettingsForm(forms.ModelForm):
    class Meta:
        model = CompanySettings
        fields = ['logo', 'name']


class RequestTypeForm(forms.ModelForm):
    class Meta:
        model = RequestType
        fields = ['name', 'department']


class SubRequestTypeForm(forms.ModelForm):
    class Meta:
        model = SubRequestType
        fields = ['name', 'main_request_type']

    def __init__(self, *args, **kwargs):
        request_type_id = kwargs.pop('request_type_id', None)
        super().__init__(*args, **kwargs)
        if request_type_id:
            self.fields['main_request_type'].queryset = RequestType.objects.filter(pk=request_type_id)
            self.fields['main_request_type'].initial = request_type_id
            self.fields['main_request_type'].widget = forms.HiddenInput()


class SubPositionForm(forms.ModelForm):
    class Meta:
        model = SubPosition
        fields = ['name', 'main_position']

    def __init__(self, *args, **kwargs):
        position_id = kwargs.pop('position_id', None)
        super().__init__(*args, **kwargs)
        if position_id:
            self.fields['main_position'].queryset = Position.objects.filter(pk=position_id)
            self.fields['main_position'].initial = position_id
            self.fields['main_position'].widget = forms.HiddenInput()


class TicketSearchForm(forms.Form):
    search = forms.CharField(required=False, label='Search Tickets')
    status = forms.ChoiceField(choices=[('open', 'Open'), ('submitted', 'Submitted'), ('in_progress', 'In Progress'), ('closed', 'Closed')], required=False)
    department = forms.ModelChoiceField(queryset=Department.objects.all(), required=False, label='Department')

    def search(self):
        query = self.cleaned_data.get('search')
        status = self.cleaned_data.get('status')
        department = self.cleaned_data.get('department')
        tickets = Ticket.objects.all()
        if query:
            tickets = tickets.filter(title__icontains=query)
        if status:
            tickets = tickets.filter(status=status)
        if department:
            tickets = tickets.filter(department=department)
        return tickets


from django import forms
from django.utils.translation import gettext_lazy as _  # Add this import at the top
from .models import FinancialWarehouse, CustomUser

class FinancialWarehouseForm(forms.ModelForm):
    item_with = forms.ModelChoiceField(
        queryset=CustomUser.objects.all(),
        label=_("Item With"),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    received_from = forms.ModelChoiceField(
        queryset=CustomUser.objects.all(),
        label=_("Received From"),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    class Meta:
        model = FinancialWarehouse
        fields = '__all__'
        exclude = ['is_taken']
        widgets = {
            'date_received': forms.DateInput(attrs={'type': 'date'}),
            'date_leave': forms.DateInput(attrs={'type': 'date'}),
            'expiry_date': forms.DateInput(attrs={'type': 'date'}),
            'buying_receipt': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'receiving_receipt': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'delivery_certificate': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'item_photo': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'property_photo': forms.ClearableFileInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['item_with'].queryset = CustomUser.objects.all().order_by('first_name', 'last_name')
        self.fields['received_from'].queryset = CustomUser.objects.all().order_by('first_name', 'last_name')
        
class FinancialWarehouseRequestForm(forms.ModelForm):
    class Meta:
        model = FinancialWarehouseRequest
        fields = ['item', 'requested_quantity', 'using_location', 'reason_for_leaving', 'request_use', 'applied_by', 'signature']
        widgets = {
            'signature': forms.ClearableFileInput(attrs={'accept': 'image/*'}),
        }


from django import forms
from .models import HRWarehouse

class HRWarehouseForm(forms.ModelForm):
    class Meta:
        model = HRWarehouse
        fields = '__all__'
        widgets = {
            'last_checkup_date': forms.DateInput(attrs={'type': 'date'}),
            'license_last_checkup': forms.DateInput(attrs={'type': 'date'}),
            'insurance_date_renew': forms.DateInput(attrs={'type': 'date'}),
            'car_photo': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'license_attachment': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'checkup_attachment': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'insurance_attachment': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'driver_id_attachment': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'driver_license_attachment': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            # If you have a signature field, include its widget as needed.
        }

from django import forms
from django.contrib.auth import get_user_model
from .models import Report

User = get_user_model()

class ReportForm(forms.ModelForm):
    # Optional extra field to filter by a specific person
    filter_person = forms.ModelChoiceField(
        queryset=User.objects.all(),
        required=False,
        label="Filter by Person"
    )

    class Meta:
        model = Report
        fields = ['title', 'report_type', 'period', 'start_date', 'end_date']
        widgets = {
            'start_date': forms.DateInput(attrs={'type': 'date'}),
            'end_date': forms.DateInput(attrs={'type': 'date'}),
        }


from django import forms
from .models import EmployeeDetails
from django import forms
from core.models import EmployeeDetails
from django.contrib.auth import get_user_model

User = get_user_model()

class EmployeeDetailsForm(forms.ModelForm):
    class Meta:
        model = EmployeeDetails
        fields = [
            'user', 'name', 'date_of_birth', 'profession',  # ✅ Added user field for Admins
            'nationality', 'passport_no', 'name_on_passport',
            'phone_number_ksa', 'relative_name', 'relative_phone_number', 
            'id_renew_date', 'duration', 'id_end_date',
            'id_attachment', 'passport_attachment', 'department'
        ]
        widgets = {
            'id_end_date': forms.DateInput(attrs={'readonly': 'readonly'}),
            'date_of_birth': forms.DateInput(attrs={'type': 'date'}),
            'id_renew_date': forms.DateInput(attrs={'type': 'date'}),
        }

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)  
        super(EmployeeDetailsForm, self).__init__(*args, **kwargs)

        user = self.request.user if self.request else None
        admin_roles = ['Admin', 'Manager', 'DCs & Secretary']

        if user and user.roles.filter(name__in=admin_roles).exists():
            # ✅ Show dropdown for Admins/Managers/DCs & Secretary
            self.fields['profession'] = forms.ChoiceField(
                choices=[(u.profession, u.profession) for u in User.objects.exclude(profession__isnull=True).distinct()],
                required=True,
                widget=forms.Select(attrs={'class': 'form-control'}),
            )
        else:
            # ✅ Auto-fill profession when creating for self
            if hasattr(user, 'profession') and user.profession:
                self.initial['profession'] = user.profession  
            self.fields['profession'].widget = forms.TextInput(attrs={'readonly': 'readonly', 'class': 'form-control'})

        # ✅ Show user dropdown only for Admins/Managers/DCs
        if user and user.roles.filter(name__in=admin_roles).exists():
            self.fields['user'].queryset = User.objects.all()
        else:
            self.fields.pop('user')  # Hide user field when creating for self

    def save(self, commit=True):
        instance = super().save(commit=False)

        # ✅ Auto-assign user when creating for self
        if not self.request.user.roles.filter(name__in=['Admin', 'Manager', 'DCs & Secretary']).exists():
            instance.user = self.request.user  

        # ✅ Auto-calculate ID End Date
        if instance.id_renew_date and instance.duration:
            instance.id_end_date = instance.id_renew_date + timedelta(days=instance.duration * 30)

        if commit:
            instance.save()
        return instance




from django import forms
from .models import AdministrativeRequest

class AdministrativeRequestForm(forms.ModelForm):
    signature = forms.ImageField(
        required=False,
        widget=forms.FileInput(attrs={'accept': 'image/*'}),
        help_text='Upload an electronic signature image (max 5MB)'
    )

    class Meta:
        model = AdministrativeRequest
        fields = '__all__'
        widgets = {
            'date': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
        }

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)

        if user and not self.instance.pk:
            self.fields['national_id'].initial = user.username or ""
            self.fields['name'].initial = f"{user.first_name} {user.last_name}".strip() or "Unknown"
            self.fields['department'].initial = getattr(user.department, 'name', 'N/A') if hasattr(user, "department") and user.department else "N/A"

        for fname in ["admin_request_nu", "department", "national_id", "name"]:
            if fname in self.fields:
                self.fields[fname].widget.attrs['readonly'] = True

        if 'created_by' in self.fields:
            self.fields['created_by'].widget = forms.HiddenInput()
            self.fields['created_by'].required = False

        # Hide approval fields for non-managers
        if not (user.is_superuser or user.groups.filter(name="Manager").exists()):
            self.fields.pop("manager_approval_status", None)
        if not (user.is_superuser or user.groups.filter(name="General Manager").exists()):
            self.fields.pop("gm_approval_status", None)


class TechnicalOfficeStorageForm(forms.ModelForm):
    class Meta:
        model = TechnicalOfficeStorage
        fields = '__all__'
        widgets = {
            'date_applied': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
            'date_receiving_apply': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
        }


from django import forms
from .models import ITWarehouse

class ITWarehouseForm(forms.ModelForm):
    class Meta:
        model = ITWarehouse
        fields = '__all__'
        widgets = {
            'date_given': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
            'date_received': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
            'signature_holder': forms.ClearableFileInput(attrs={'accept': 'image/*'}),
        }

    def __init__(self, *args, **kwargs):
        # Pop the user from kwargs if provided; default to None.
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Check if the user exists and has roles before accessing them.
        if self.user and hasattr(self.user, 'roles'):
            is_manager_or_admin = self.user.roles.filter(
                name__in=['Manager', 'Admin', 'General Manager']
            ).exists()
        else:
            is_manager_or_admin = False

        # If not a manager/admin and a signature exists, lock all fields.
        if not is_manager_or_admin and self.instance.signature_holder:
            for field_name in self.fields:
                self.fields[field_name].widget.attrs['readonly'] = True
                self.fields[field_name].widget.attrs['disabled'] = True

        # If signature_holder is not set, ensure signing fields are active.
        if not self.instance.signature_holder:
            self.fields['signature_holder'].widget.attrs.pop('readonly', None)
            self.fields['signature_holder'].widget.attrs.pop('disabled', None)

class ITRequestForm(forms.ModelForm):
    class Meta:
        model = ITRequest
        fields = ['title', 'description', 'it_request_type', 'priority', 'notes', 'actions']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)  # Capture the logged-in user
        super().__init__(*args, **kwargs)

    def save(self, commit=True):
        instance = super().save(commit=False)

        # Check the underlying ID field instead of the relation itself
        if self.user and not instance.created_by_id:
            instance.created_by = self.user

        if commit:
            instance.save()
        
        return instance

class MyPossessionForm(forms.ModelForm):
    class Meta:
        model = MyPossession
        fields = '__all__'
        widgets = {
            'signature': forms.ClearableFileInput(attrs={'accept': 'image/*'}),
        }


class ContractorForm(forms.ModelForm):
    class Meta:
        model = Contractor
        fields = '__all__'


from django import forms
from .models import CompanyClearance

from django import forms
from .models import CompanyClearance

from django import forms
from .models import CompanyClearance

# core/forms.py
from django import forms
from .models import CompanyClearance

class CompanyClearanceForm(forms.ModelForm):
    class Meta:
        model = CompanyClearance
        # Only include the fields the employee should input
        fields = ['last_day_of_work', 'leaving_reason']

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        self.fields['last_day_of_work'].widget.attrs.update({'class': 'form-control'})
        self.fields['leaving_reason'].widget.attrs.update({'class': 'form-control'})

        # Optionally set initial values for display purposes (not rendered as inputs)
        if user:
            self.initial['first_name'] = user.first_name
            self.initial['last_name'] = user.last_name
            self.initial['profession'] = user.profession
            self.initial['national_id_or_iqama_no'] = user.national_id
            # Assuming your custom user has a related department with a name attribute
            self.initial['department'] = user.department.name if hasattr(user, 'department') and user.department else "Not Assigned"


class AccountForm(forms.ModelForm):
    class Meta:
        model = Account
        fields = ['name', 'account_type', 'description']


class JournalEntryForm(forms.ModelForm):
    class Meta:
        model = JournalEntry
        fields = ['date', 'description']


class JournalEntryLineForm(forms.ModelForm):
    class Meta:
        model = JournalEntryLine
        fields = ['journal_entry', 'account', 'debit', 'credit']


class EmployeeAllowanceForm(forms.ModelForm):
    class Meta:
        model = EmployeeAllowance
        fields = ['employee', 'allowance_type', 'amount', 'frequency', 'start_date', 'end_date']


class FinancialAdvanceForm(forms.ModelForm):
    class Meta:
        model = FinancialAdvance
        fields = ['employee', 'amount', 'reason', 'date_issued', 'repayment_date']


class EndOfServiceRewardForm(forms.ModelForm):
    class Meta:
        model = EndOfServiceReward
        fields = ['employee', 'amount', 'date_issued']


class CRMCustomerForm(forms.ModelForm):
    class Meta:
        model = CRMCustomer
        fields = ['name', 'email', 'phone_number', 'address', 'notes']


class CRMLeadForm(forms.ModelForm):
    class Meta:
        model = CRMLead
        fields = ['customer', 'status', 'notes']


class ERPPurchaseOrderForm(forms.ModelForm):
    class Meta:
        model = ERPPurchaseOrder
        fields = ['supplier', 'order_date', 'total_amount', 'status']


class ERPInvoiceForm(forms.ModelForm):
    class Meta:
        model = ERPInvoice
        fields = ['purchase_order', 'invoice_number', 'invoice_date', 'total_amount', 'status']


class AccountingEntryForm(forms.ModelForm):
    class Meta:
        model = AccountingEntry
        fields = ['date', 'description', 'debit', 'credit', 'account']


class CRMTicketForm(forms.ModelForm):
    class Meta:
        model = CRMTicket
        fields = ['title', 'description', 'status']


class ERPEntryForm(forms.ModelForm):
    class Meta:
        model = ERPEntry
        fields = ['description']


class SalaryForm(forms.ModelForm):
    class Meta:
        model = Salary
        fields = ['employee', 'amount', 'date_issued']

# forms.py
from django import forms
from .models import StartWorkPermit

from django import forms
from .models import StartWorkPermit

from django import forms
from .models import StartWorkPermit

from django import forms
from .models import StartWorkPermit
from django.contrib.auth import get_user_model

User = get_user_model()

class StartWorkPermitForm(forms.ModelForm):
    class Meta:
        model = StartWorkPermit
        fields = ['profession', 'start_date', 'notes']
        widgets = {
            'start_date': forms.DateInput(attrs={'type': 'date'}),
            'notes': forms.Textarea(attrs={'rows': 3}),
        }

    def __init__(self, *args, **kwargs):
        """ Auto-fill profession when user creates their own work permit """
        self.request = kwargs.pop('request', None)  # Extract request object
        super(StartWorkPermitForm, self).__init__(*args, **kwargs)

        if self.request and self.request.user:
            user = self.request.user

            if user.roles.filter(name__in=["Admin", "Manager", "DCs & Secretary"]).exists():
                # Admins/Managers/DCs & Secretary can select profession
                self.fields['profession'] = forms.ChoiceField(
                    choices=[(u.profession, u.profession) for u in User.objects.exclude(profession__isnull=True).exclude(profession="")],
                    required=True,
                )
            else:
                # Normal employees get profession auto-filled
                self.fields['profession'].widget = forms.TextInput(attrs={'readonly': 'readonly'})
                self.initial['profession'] = user.profession if user.profession else "Not Assigned"

class StartWorkPermitStatusForm(forms.ModelForm):
    class Meta:
        model = StartWorkPermit
        fields = ['status']

class HealthSafetyForm(forms.ModelForm):
    class Meta:
        model = HealthSafety
        fields = ['title', 'description', 'date']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date'}),
            'description': forms.Textarea(attrs={'rows': 4}),
        }


class WorkshopForm(forms.ModelForm):
    class Meta:
        model = Workshop
        fields = ['name', 'date', 'description']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date'}),
            'description': forms.Textarea(attrs={'rows': 4}),
        }
