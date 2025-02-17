from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser, Permission
from django.utils import timezone
from django.db.models import Max
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.utils import timezone
from datetime import date, timedelta  # If you're already importing date
# OR
from datetime import timedelta  # If you just need timedelta

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _


from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from django.utils.translation import gettext_lazy as _

from django.db import models
from django.contrib.auth.models import AbstractUser, Permission, Group
from django.utils.translation import gettext as _

class Role(models.Model):
    name = models.CharField(max_length=255, unique=True)
    permissions = models.ManyToManyField(Permission, blank=True)

    def __str__(self):
        return self.name

class CustomUser(AbstractUser):
    national_id = models.CharField(
        max_length=255,
        unique=True,
        null=True,
        blank=True,
        verbose_name=_('National ID'),
        help_text=_('Enter your National ID number')
    )
    profession = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name=_("Profession"),
        help_text=_("Enter your profession")
    )
    roles = models.ManyToManyField(
        Role,
        related_name='users',
        verbose_name=_('Roles'),
        blank=True
    )
    position = models.ForeignKey(
        'Position',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_('Position')
    )
    department = models.ForeignKey(
        'Department',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_('Department')
    )
    groups = models.ManyToManyField(
        Group,
        related_name='custom_user_set',
        blank=True,
        help_text=_('The groups this user belongs to. A user will get all permissions granted to each of their groups.'),
        verbose_name=_('groups'),
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='custom_user_set',
        blank=True,
        help_text=_('Specific permissions for this user.'),
        verbose_name=_('user permissions'),
    )

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        ordering = ['username']

    def assign_role(self, role):
        """Assign a role to the user"""
        self.roles.add(role)
        self.save()

    def remove_role(self, role):
        """Remove a role from the user"""
        self.roles.remove(role)
        self.save()

    def has_role(self, role_name):
        """Check if user has a specific role"""
        return self.roles.filter(name=role_name).exists()

    def get_full_name(self):
        """Return the first_name plus the last_name, with a space in between"""
        full_name = f"{self.first_name} {self.last_name}"
        return full_name.strip()

    def get_profession(self):
        """Return the user's profession or 'Not Specified' if empty"""
        return self.profession if self.profession else "Not Specified"

    def get_position_name(self):
        """Return the position name if it exists"""
        return self.position.name if self.position else None

    def get_department_name(self):
        """Return the department name if it exists"""
        return self.department.name if self.department else None

    def __str__(self):
        if self.position:
            return f"{self.position.name} - {self.get_full_name()} - {self.get_profession()}"
        return f"{self.get_full_name()} - {self.get_profession()}"

    def save(self, *args, **kwargs):
        """Ensure username & email are always lowercase"""
        if self.username:
            self.username = self.username.lower()
        if self.email:
            self.email = self.email.lower()
        super().save(*args, **kwargs)

class Position(models.Model):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class Department(models.Model):
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name


class RequestType(models.Model):
    name = models.CharField(max_length=100)
    department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='request_types')

    def __str__(self):
        return self.name


class SubRequestType(models.Model):
    name = models.CharField(max_length=100)
    main_request_type = models.ForeignKey(RequestType, on_delete=models.CASCADE, related_name='sub_request_types')

    def __str__(self):
        return self.name


class Ticket(models.Model):
    STATUS_CHOICES = [
        ('submitted', 'Submitted'),
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('Accepted', 'Accepted'),
        ('rejected', 'Rejected'),
        ('canceled', 'Canceled'),
    ]
    title = models.CharField(max_length=255)
    description = models.TextField()
    status = models.CharField(max_length=255, choices=STATUS_CHOICES, default='open')
    applied_by = models.ForeignKey(CustomUser, related_name='applied_tickets', on_delete=models.CASCADE)
    applied_for = models.ForeignKey(CustomUser, related_name='assigned_tickets', on_delete=models.CASCADE, null=True, blank=True)
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    request_type = models.ForeignKey(RequestType, on_delete=models.CASCADE)
    sub_request_type = models.ForeignKey(SubRequestType, on_delete=models.CASCADE, null=True, blank=True)
    assigned_to = models.ForeignKey(CustomUser, related_name='assigned_to_tickets', on_delete=models.CASCADE, null=True, blank=True)
    attachment = models.FileField(upload_to='attachments/', null=True, blank=True)
    date_created = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.title

    def get_status_class(self):
        return self.status.replace(' ', '_').lower()

    @property
    def get_assigned_to_full_name(self):
        if self.assigned_to:
            return f"{self.assigned_to.first_name} {self.assigned_to.last_name}"
        return ""

    def get_applied_by_full_name(self):
        if self.applied_by:
            return f"{self.applied_by.first_name} {self.applied_by.last_name}"
        return ""

    def get_applied_for_full_name(self):
        if self.applied_for:
            return f"{self.applied_for.first_name} {self.applied_for.last_name}"
        return ""


class CompanySettings(models.Model):
    name = models.CharField(max_length=255)
    logo = models.ImageField(upload_to='logos/')

    def __str__(self):
        return self.name


class SubPosition(models.Model):
    name = models.CharField(max_length=100)
    main_position = models.ForeignKey(Position, on_delete=models.CASCADE, related_name='sub_positions')

    def __str__(self):
        return self.name

class FinancialWarehouse(models.Model):
    item_no = models.IntegerField(editable=False, unique=True)
    item_name = models.CharField(max_length=255)
    description = models.TextField()
    date_received = models.DateField()
    expiry_date = models.DateField()
    date_leave = models.DateField(null=True, blank=True)
    storing_location = models.CharField(max_length=255)
    quantity = models.IntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    vat_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=15.0)
    total_vat = models.DecimalField(max_digits=10, decimal_places=2, editable=False)
    total_price = models.DecimalField(max_digits=10, decimal_places=2, editable=False)
    net_price = models.DecimalField(max_digits=10, decimal_places=2, editable=False)
    serial_number = models.CharField(max_length=255, null=True, blank=True)
    buying_receipt = models.FileField(upload_to='financial_warehouse/buying_receipts/', null=True, blank=True)
    receiving_receipt = models.FileField(upload_to='financial_warehouse/receiving_receipts/', null=True, blank=True)
    delivery_certificate = models.FileField(upload_to='financial_warehouse/delivery_certificates/', null=True, blank=True)
    item_photo = models.ImageField(upload_to='financial_warehouse/item_photos/', null=True, blank=True)
    property_photo = models.ImageField(upload_to='financial_warehouse/property_photos/', null=True, blank=True)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='created_items')
    created_at = models.DateTimeField(auto_now_add=True)
    item_with = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='items_with')
    received_from = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='items_received_from')
    is_taken = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.item_no:
            max_item_no = FinancialWarehouse.objects.aggregate(Max('item_no'))['item_no__max']
            self.item_no = (max_item_no or 0) + 1
        self.net_price = self.price * self.quantity
        self.total_vat = self.net_price * (self.vat_percentage / 100)
        self.total_price = self.net_price + self.total_vat
        super().save(*args, **kwargs)

    def __str__(self):
        return self.item_name

class FinancialWarehouseRequest(models.Model):
    REQUEST_USE_CHOICES = [
        ('Permanent', 'Permanent use in project'),
        ('Temporary', 'Temporary usage'),
    ]
    item = models.ForeignKey(FinancialWarehouse, on_delete=models.CASCADE)
    requested_quantity = models.PositiveIntegerField()
    using_location = models.ForeignKey(Department, on_delete=models.CASCADE)
    reason_for_leaving = models.TextField()
    request_use = models.CharField(max_length=50, choices=REQUEST_USE_CHOICES)
    applied_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    applied_at = models.DateTimeField(auto_now_add=True)
    signature = models.ImageField(upload_to='signatures/', null=True, blank=True)

    def __str__(self):
        return f"Request for {self.item.item_name} by {self.applied_by}"


from django.db import models
from django.utils import timezone
from core.models import CustomUser  # Assuming CustomUser is in core.models

from django.db import models
from django.utils import timezone
from dateutil.relativedelta import relativedelta  # Import relativedelta for month arithmetic

class HRWarehouse(models.Model):
    item_no = models.CharField(max_length=100)
    item_type = models.CharField(max_length=255)
    plate_number = models.CharField(max_length=255, null=True, blank=True)
    last_checkup_date = models.DateField()
    duration_of_checkup = models.IntegerField(help_text="Duration in months")  # Now in months
    end_checkup_date = models.DateField(blank=True, null=True)
    license_last_checkup = models.DateField()
    duration_of_license = models.IntegerField(help_text="Duration in months")  # Now in months
    end_license_date = models.DateField(blank=True, null=True)
    insurance_date_renew = models.DateField()
    duration_of_insurance = models.IntegerField(help_text="Duration in months")  # Now in months
    end_insurance_date = models.DateField(blank=True, null=True)
    current_driver = models.ForeignKey('CustomUser', related_name='current_driver', on_delete=models.SET_NULL, null=True)
    location = models.CharField(max_length=255)
    traffic_violation_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    traffic_violation_attachment = models.FileField(upload_to='hr_warehouse/traffic_violations/', null=True, blank=True)
    car_photo = models.ImageField(upload_to='hr_warehouse/car_photos/', null=True, blank=True)
    license_attachment = models.FileField(upload_to='hr_warehouse/license_attachments/', null=True, blank=True)
    checkup_attachment = models.FileField(upload_to='hr_warehouse/checkup_attachments/', null=True, blank=True)
    insurance_attachment = models.FileField(upload_to='hr_warehouse/insurance_attachments/', null=True, blank=True)
    driver_id_attachment = models.FileField(upload_to='hr_warehouse/driver_id_attachments/', null=True, blank=True)
    driver_license_attachment = models.FileField(upload_to='hr_warehouse/driver_license_attachments/', null=True, blank=True)
    created_by = models.ForeignKey('CustomUser', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Calculate end_checkup_date by adding the duration in months
        if self.last_checkup_date and self.duration_of_checkup:
            self.end_checkup_date = self.last_checkup_date + relativedelta(months=self.duration_of_checkup)

        # Calculate end_license_date by adding the duration in months
        if self.license_last_checkup and self.duration_of_license:
            self.end_license_date = self.license_last_checkup + relativedelta(months=self.duration_of_license)

        # Calculate end_insurance_date by adding the duration in months
        if self.insurance_date_renew and self.duration_of_insurance:
            self.end_insurance_date = self.insurance_date_renew + relativedelta(months=self.duration_of_insurance)

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.item_type} (Item No: {self.item_no})"

from django.db import models
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _

class Report(models.Model):
    REPORT_TYPES = [
        ('tickets', 'Tickets'),
        ('it_requests', 'IT Requests'),
        ('it_warehouse', 'IT Warehouse'),
        ('hr_warehouse', 'Cars and Heavy Equipment'),
        ('administrative', 'Administrative Requests'),
        ('financial', 'Financial Warehouse'),
        ('clearance', 'Company Clearance'),
        ('work_permit', 'Work Permit'),
    ]

    PERIOD_CHOICES = [
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('yearly', 'Yearly'),
    ]

    title = models.CharField(max_length=200)
    report_type = models.CharField(max_length=50, choices=REPORT_TYPES)
    period = models.CharField(max_length=20, choices=PERIOD_CHOICES)
    start_date = models.DateField()
    end_date = models.DateField()
    created_by = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    filters = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} - {self.get_report_type_display()}"


from django.db import models
from django.conf import settings
from datetime import timedelta, datetime
import random

from django.db import models
from django.conf import settings
from datetime import datetime, timedelta
import random

from django.db import models
from django.conf import settings
from datetime import timedelta

from django.db import models
from django.conf import settings
from datetime import datetime, timedelta
import random
from django.db import models
from django.conf import settings
from datetime import datetime, timedelta


from django.db import models
from django.conf import settings
from datetime import timedelta, datetime

from django.db import models
from django.conf import settings

from django.db import models
from django.conf import settings
from datetime import timedelta, datetime

from django.db import models
from django.conf import settings
from datetime import datetime, timedelta

from django.db import models
from django.conf import settings
from datetime import datetime, timedelta
from django.db import models
from django.conf import settings
from datetime import datetime, timedelta

from django.db import models
from django.conf import settings
from datetime import datetime, timedelta

from django.db import models
from django.conf import settings
from datetime import datetime, timedelta

class EmployeeDetails(models.Model):
    employee_no = models.CharField(max_length=100, unique=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="employee_details"
    )
    profession = models.CharField(max_length=100, blank=True, null=True)  # ✅ Auto-filled from user
    iqama_id_no = models.CharField(max_length=255, blank=True, null=True)
    name = models.CharField(max_length=255)
    date_of_birth = models.DateField()
    nationality = models.CharField(max_length=255)
    passport_no = models.CharField(max_length=255)
    name_on_passport = models.CharField(max_length=255)
    phone_number_ksa = models.CharField(max_length=10)
    relative_name = models.CharField(max_length=255)
    relative_phone_number = models.CharField(max_length=15)
    id_renew_date = models.DateField()
    duration = models.IntegerField()
    id_end_date = models.DateField(blank=True, null=True)
    id_attachment = models.FileField(upload_to='employee_details/id_attachments/', null=True, blank=True)
    passport_attachment = models.FileField(upload_to='employee_details/passport_attachments/', null=True, blank=True)
    department = models.ForeignKey('Department', on_delete=models.SET_NULL, null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="created_employees")
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        """Ensure profession, user, and ID End Date are set correctly"""

        if not self.user:  
            raise ValueError("User must be assigned before saving EmployeeDetails.")

        if not self.profession and hasattr(self.user, 'profession') and self.user.profession:
            self.profession = self.user.profession  # ✅ Auto-fill profession
        
        if not self.iqama_id_no and hasattr(self.user, 'national_id'):
            self.iqama_id_no = self.user.national_id  # ✅ Auto-fill iqama_id_no
        
        if self.id_renew_date and self.duration:
            self.id_end_date = self.id_renew_date + timedelta(days=self.duration * 30)  # ✅ Auto-calculate

        if not self.employee_no:
            self.employee_no = self.generate_employee_number()

        super().save(*args, **kwargs)

    def generate_employee_number(self):
        """Generate a unique Employee Number in the format EMPYYMMXXX"""
        timestamp = datetime.now().strftime('%y%m')  
        latest_employee = EmployeeDetails.objects.order_by('-created_at').first()

        if latest_employee and latest_employee.employee_no.startswith('EMP'):
            try:
                last_num = int(latest_employee.employee_no[-3:])  
                new_num = str(last_num + 1).zfill(3)
            except ValueError:
                new_num = '001'
        else:
            new_num = '001'

        return f'EMP{timestamp}{new_num}'

    def __str__(self):
        return f"{self.name} ({self.employee_no})"

from django.db import models
from django.conf import settings
from django.db.models import Max
import os

class AdministrativeRequest(models.Model):
    ADMIN_REQUEST_COMPANY_CHOICES = [
        ('SBG', 'SBG'),
        ('HIC', 'HIC'),
    ]
    ADMIN_REQUEST_TYPE_CHOICES = [
        ('Leave on Vacation Request', 'Leave on Vacation Request'),
        ('Exit and Return Visa', 'Exit and Return Visa'),
        ('National ID / Iqama', 'National ID / Iqama'),
        ('Passport', 'Passport'),
        ('Profession Edit', 'Profession Edit'),
        ('Passport Department gov', 'Passport Department gov'),
        ('Employment Letter', 'Employment Letter'),
        ('Receive Vehicle', 'Receive Vehicle'),
    ]
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('In Progress', 'In Progress'),
        ('Completed', 'Completed'),
        ('Rejected', 'Rejected'),
    ]
    EXPLANATION_CHOICES = [
        ('Vacation Leave', 'Vacation Leave'),
        ('Business Travel', 'Business Travel'),
        ('Training Request', 'Training Request'),
        ('Equipment Request', 'Equipment Request'),
        ('Work Permit Renewal', 'Work Permit Renewal'),
        ('Salary Certificate', 'Salary Certificate'),
        ('Other', 'Other'),
    ]
    APPROVAL_STATUS_CHOICES = [
        ('Open', 'Open'),
        ('Accepted', 'Accepted'),
        ('Rejected', 'Rejected'),
    ]

    admin_request_nu = models.CharField(
        max_length=100,
        unique=True,
        blank=True,
        null=True,
        verbose_name='Request Number'
    )
    admin_request_company = models.CharField(max_length=3, choices=ADMIN_REQUEST_COMPANY_CHOICES)
    admin_request_type = models.CharField(max_length=50, choices=ADMIN_REQUEST_TYPE_CHOICES)
    national_id = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    department = models.CharField(max_length=255)
    explanation_of_request = models.CharField(max_length=50, choices=EXPLANATION_CHOICES)
    notes = models.TextField(blank=True, null=True)
    date = models.DateTimeField(auto_now_add=True)

    # Employee Signature
    signature = models.ImageField(upload_to='signatures/', null=True, blank=True)

    # Manager & GM Approval Status
    manager_approval_status = models.CharField(
        max_length=10, choices=APPROVAL_STATUS_CHOICES, default='Open', verbose_name="Manager Approval"
    )
    gm_approval_status = models.CharField(
        max_length=10, choices=APPROVAL_STATUS_CHOICES, default='Open', verbose_name="GM Approval"
    )

    # General Request Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')

    # Created By (Employee)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='administrative_requests'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def generate_request_number(self):
        """ Generate a unique request number like 'admreq001', 'admreq002'... """
        prefix = "admreq"
        last_req = AdministrativeRequest.objects.filter(
            admin_request_nu__startswith=prefix
        ).aggregate(Max('admin_request_nu'))['admin_request_nu__max']

        if last_req:
            numeric_part = last_req.replace(prefix, "")
            try:
                number = int(numeric_part) + 1
            except ValueError:
                number = 1
        else:
            number = 1

        return f"{prefix}{str(number).zfill(3)}"

    def save(self, *args, **kwargs):
        """ 
        - Ensure request number is generated before saving.
        - Remove old signature if a new one is uploaded.
        """
        if not self.pk and not self.admin_request_nu:
            self.admin_request_nu = self.generate_request_number()

        if self.pk:
            existing = AdministrativeRequest.objects.get(pk=self.pk)
            if existing.signature and self.signature and existing.signature != self.signature:
                old_signature_path = existing.signature.path
                if os.path.exists(old_signature_path):
                    os.remove(old_signature_path)

        super().save(*args, **kwargs)

    def __str__(self):
        return self.admin_request_nu or 'New Request'



class TechnicalOfficeStorage(models.Model):
    FILE_TYPE_CHOICES = [
        ('Request of Mir', 'Request of Mir'),
        ('Request of WiR', 'Request of WiR'),
        ('Appling for Code', 'Appling for Code'),
    ]
    CODE_CHOICES = [
        ('A+', 'A+'),
        ('A', 'A'),
        ('A-', 'A-'),
        ('B+', 'B+'),
        ('B', 'B'),
        ('B-', 'B-'),
        ('C', 'C'),
        ('D', 'D'),
    ]
    no = models.CharField(max_length=100)
    file_type = models.CharField(max_length=50, choices=FILE_TYPE_CHOICES)
    file_name = models.CharField(max_length=255)
    description = models.TextField()
    location = models.CharField(max_length=255)
    date_applied = models.DateTimeField()
    date_receiving_apply = models.DateTimeField()
    code = models.CharField(max_length=2, choices=CODE_CHOICES)
    notes_for_approval_or_rejection = models.TextField(blank=True, null=True)
    attachment = models.FileField(upload_to='technical_office_attachments/')
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.no


from django.db import models
from django.core.validators import RegexValidator
from django.contrib.auth import get_user_model

User = get_user_model()
from django.db import models
from django.contrib.auth.models import User
from django.core.validators import RegexValidator
from django.utils.timezone import now


from django.db import models
from django.conf import settings  # Use AUTH_USER_MODEL
from django.core.validators import RegexValidator
from django.utils.timezone import now


from django.db import models
from django.utils.text import slugify

from django.db import models

from django.db import models
from django.utils.timezone import now
from core.models import CustomUser  # Assuming CustomUser is defined elsewhere

from django.db import models
from django.conf import settings  # Assuming CustomUser is set as the user model

class ITWarehouse(models.Model):
    ITEM_TYPE_CHOICES = [
        ('Sim Card', 'Sim Card'),
        ('Router', 'Router'),
        ('Switch', 'Switch'),
        ('Wifi Access Point', 'Wifi Access Point'),
        ('CCTV', 'CCTV'),
        ('NVR', 'NVR'),
        ('DVR', 'DVR'),
        ('Normal Camera', 'Normal Camera'),
        ('Hard Disk or SSD External', 'Hard Disk or SSD External'),
        ('Laptop', 'Laptop'),
        ('PC', 'PC'),
        ('PC AIO', 'PC AIO'),
        ('Drone', 'Drone'),
        ('Monitor', 'Monitor'),
        ('Other', 'Other'),
    ]

    CONDITION_CHOICES = [
        ('New', 'New'),
        ('Used', 'Used'),
    ]

    item_no = models.CharField(max_length=100, unique=True, editable=False)  # Follows "ITWARE-0001" pattern
    item_type = models.CharField(max_length=50, choices=ITEM_TYPE_CHOICES)
    item_model_name = models.CharField(max_length=255)
    description = models.TextField()
    specifications = models.TextField()
    condition = models.CharField(max_length=4, choices=CONDITION_CHOICES)
    item_with = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='item_with')
    given_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='given_by')
    quantity = models.PositiveIntegerField()
    serial_number = models.CharField(max_length=255, blank=True, null=True)
    date_given = models.DateTimeField()
    date_received = models.DateTimeField(blank=True, null=True)
    attachments = models.FileField(upload_to='it_warehouse_attachments/', blank=True, null=True)
    signature_holder = models.ImageField(upload_to='signatures/', null=True, blank=True)
    signature_department_manager = models.ImageField(upload_to='signatures/', null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    given_by_name = models.CharField(max_length=255, blank=True, null=True)  # Store first + last name
    item_with_name = models.CharField(max_length=255, blank=True, null=True)  # Store first + last name

    def save(self, *args, **kwargs):
        # Auto-generate a unique warehouse item number before saving
        if not self.item_no:
            next_number = 1
            while True:
                candidate = f"ITWARE-{next_number:04d}"  # ITWARE-0001, ITWARE-0002, etc.
                if not ITWarehouse.objects.filter(item_no=candidate).exists():
                    self.item_no = candidate
                    break
                next_number += 1
        super().save(*args, **kwargs)

    def __str__(self):
        return self.item_no

CustomUser = get_user_model()


class ITRequest(models.Model):
    IT_REQUEST_TYPE_CHOICES = [
        ('Checkup', 'Checkup'),
        ('PC', 'PC'),
        ('Laptop', 'Laptop'),
        ('Monitor', 'Monitor'),
        ('Camera', 'Camera'),
        ('Internet', 'Internet'),
        ('Network Devices', 'Network Devices'),
        ('Servers', 'Servers'),
        ('Software', 'Software'),
        ('Hardware', 'Hardware'),
        ('Cable Termination', 'Cable Termination'),
        ('Biometric Devices', 'Biometric Devices'),
        ('Fingerprint Attendance Devices', 'Fingerprint Attendance Devices'),
        ('ERP Accountant System', 'ERP Accountant System'),
        ('Cloud Storage', 'Cloud Storage'),
        ('Phone', 'Phone'),
        ('New Design Cabling and Termination', 'New Design Cabling and Termination'),
        ('Security Devices', 'Security Devices'),
        ('New Project Related IT Consulting and Calculations', 'New Project Related IT Consulting and Calculations'),
        ('Annual IT Department Costs', 'Annual IT Department Costs'),
        ('Personal Requests', 'Personal Requests'),
    ]

    PRIORITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
    ]

    STATUS_CHOICES = [
        ('Open', 'Open'),
        ('In Progress', 'In Progress'),
        ('Completed', 'Completed'),
        ('Rejected', 'Rejected'),
    ]

    request_no = models.CharField(max_length=100, unique=True, editable=False)
    title = models.CharField(max_length=255)
    description = models.TextField()
    it_request_type = models.CharField(max_length=100, choices=IT_REQUEST_TYPE_CHOICES)
    name = models.CharField(max_length=255)
    date_applied = models.DateField(default=now, editable=False)
    priority = models.CharField(max_length=100, choices=PRIORITY_CHOICES)
    notes = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=100, choices=STATUS_CHOICES, default='Open')
    actions = models.TextField(blank=True, null=True, default='')
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Auto-generate a unique request number before saving
        if not self.request_no:
            next_number = 1
            while True:
                candidate = f"ITREQ-{next_number:04d}"
                if not ITRequest.objects.filter(request_no=candidate).exists():
                    self.request_no = candidate
                    break
                next_number += 1

        # Ensure the name is set (using created_by if available)
        if not self.name:
            self.name = self.created_by.get_full_name() if self.created_by else ''

        # Ensure actions is not None
        self.actions = self.actions or ''

        super().save(*args, **kwargs)
    
class MyPossession(models.Model):
    no = models.CharField(max_length=50)
    item_type = models.CharField(max_length=100)
    quantity = models.PositiveIntegerField()
    date_received = models.DateField()
    date_returned = models.DateField(null=True, blank=True)
    attachment_paper = models.FileField(upload_to='attachments/', null=True, blank=True)
    attachment_item_condition = models.FileField(upload_to='attachments/', null=True, blank=True)
    status = models.CharField(max_length=50)
    signature_of_receiving = models.ImageField(upload_to='signatures/', null=True, blank=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='possessions')
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='created_possessions')

    def __str__(self):
        return f"{self.item_type} ({self.quantity})"


class Contractor(models.Model):
    name = models.CharField(max_length=255)
    gov_registration_number = models.CharField(max_length=100)
    tax_number = models.CharField(max_length=100)
    email = models.EmailField()
    phone_number = models.CharField(max_length=15)
    address = models.TextField()
    contracts_attachment = models.FileField(upload_to='contracts/')
    quantity_of_contracts = models.IntegerField()
    contractor_statement_invoices = models.TextField()
    paid = models.DecimalField(max_digits=10, decimal_places=2)
    not_paid = models.DecimalField(max_digits=10, decimal_places=2)
    specify_which_contract_not_paid = models.TextField()
    total = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return self.name


from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

from django.db import models
from django.conf import settings

from django.db import models
from django.conf import settings

from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

# core/models.py
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

# core/models.py
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

class CompanyClearance(models.Model):
    VACATION = 'Vacation'
    FINAL_LEAVE = 'Final Leave'
    LEAVING_REASONS = [
        (VACATION, _('Vacation')),
        (FINAL_LEAVE, _('Final Leave')),
    ]

    # Employee details (populated from your custom user)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    profession = models.CharField(max_length=100)
    national_id_or_iqama_no = models.CharField(max_length=100)
    department = models.CharField(max_length=100, blank=True, null=True)
    today_date = models.DateField(auto_now_add=True)
    last_day_of_work = models.DateField()
    leaving_reason = models.CharField(max_length=50, choices=LEAVING_REASONS)
    status = models.CharField(
        max_length=50,
        choices=[('Pending', 'Pending'), ('Approved', 'Approved'), ('Rejected', 'Rejected')],
        default='Pending'
    )
    notes = models.TextField(blank=True, null=True)
    is_locked = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.first_name} {self.last_name} - {self.leaving_reason}"

    @property
    def employee_name(self):
        return f"{self.first_name} {self.last_name}"

    def get_signatures(self):
        return self.signatures.all()


class ClearanceSignature(models.Model):
    clearance = models.ForeignKey(CompanyClearance, related_name='signatures', on_delete=models.CASCADE)
    manager = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    signature = models.ImageField(upload_to='signatures/')
    approval_note = models.TextField(blank=True, null=True)
    status = models.CharField(
        max_length=50,
        choices=[('Approved', 'Approved'), ('Rejected', 'Rejected')]
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('clearance', 'manager')  # Each manager may sign once per clearance

    def __str__(self):
        return f"{self.manager.get_full_name()} - {self.status}"

class Signature(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='signatures')
    image = models.ImageField(upload_to='signatures/')
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name


class Account(models.Model):
    ACCOUNT_TYPES = [
        ('Asset', 'Asset'),
        ('Liability', 'Liability'),
        ('Equity', 'Equity'),
        ('Revenue', 'Revenue'),
        ('Expense', 'Expense'),
    ]
    name = models.CharField(max_length=255)
    account_type = models.CharField(max_length=20, choices=ACCOUNT_TYPES)
    description = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.name


class JournalEntry(models.Model):
    date = models.DateField(default=timezone.now)
    description = models.TextField()
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Journal Entry on {self.date}"


class JournalEntryLine(models.Model):
    journal_entry = models.ForeignKey(JournalEntry, related_name='lines', on_delete=models.CASCADE)
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    debit = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    credit = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    def __str__(self):
        return f"{self.account.name} - Debit: {self.debit}, Credit: {self.credit}"


class EmployeeAllowance(models.Model):
    employee = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    allowance_type = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    frequency = models.CharField(max_length=50, choices=[('Monthly', 'Monthly'), ('Annually', 'Annually')])
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"{self.allowance_type} for {self.employee.username}"


class FinancialAdvance(models.Model):
    employee = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    reason = models.TextField()
    date_issued = models.DateField(default=timezone.now)
    repayment_date = models.DateField()

    def __str__(self):
        return f"Advance for {self.employee.username} - {self.amount}"


class EndOfServiceReward(models.Model):
    employee = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date_issued = models.DateField(default=timezone.now)

    def __str__(self):
        return f"End of Service Reward for {self.employee.username}"


class CRMCustomer(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField()
    phone_number = models.CharField(max_length=15)
    address = models.TextField()
    notes = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.name


class CRMLead(models.Model):
    customer = models.ForeignKey(CRMCustomer, on_delete=models.CASCADE)
    status = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Lead for {self.customer.name}"


class ERPPurchaseOrder(models.Model):
    supplier = models.ForeignKey(Contractor, on_delete=models.CASCADE)
    order_date = models.DateField(default=timezone.now)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=255)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"PO for {self.supplier.name}"


class ERPInvoice(models.Model):
    purchase_order = models.ForeignKey(ERPPurchaseOrder, on_delete=models.CASCADE)
    invoice_number = models.CharField(max_length=100)
    invoice_date = models.DateField(default=timezone.now)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=255)

    def __str__(self):
        return f"Invoice {self.invoice_number} for PO {self.purchase_order.id}"


class AccountingEntry(models.Model):
    date = models.DateField(default=timezone.now)
    description = models.TextField()
    debit = models.DecimalField(max_digits=10, decimal_places=2)
    credit = models.DecimalField(max_digits=10, decimal_places=2)
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Accounting Entry on {self.date} - {self.description}"


class CRMTicket(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    status = models.CharField(max_length=100)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class ERPEntry(models.Model):
    description = models.TextField()
    date_created = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

    def __str__(self):
        return f"ERP Entry {self.id}"


class Salary(models.Model):
    employee = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date_issued = models.DateField(default=timezone.now)

    def __str__(self):
        return f"Salary for {self.employee.username} - {self.amount}"


class Sale(models.Model):
    item_name = models.CharField(max_length=255)
    quantity = models.PositiveIntegerField()
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    total_price = models.DecimalField(max_digits=10, decimal_places=2, editable=False)
    customer = models.CharField(max_length=255, null=True, blank=True)
    sale_date = models.DateField(default=timezone.now)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    notes = models.TextField(null=True, blank=True)

    def save(self, *args, **kwargs):
        self.total_price = self.quantity * self.unit_price
        super(Sale, self).save(*args, **kwargs)

    def __str__(self):
        return f"Sale of {self.item_name} on {self.sale_date}"

# models.py
from django.conf import settings
from django.db import models

from django.db import models
from django.conf import settings

from django.db import models
from django.conf import settings

from django.conf import settings
from django.db import models

from django.conf import settings
from django.db import models

from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

class StartWorkPermit(models.Model):
    employee = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    profession = models.CharField(max_length=100, blank=True, null=True)  # ✅ Auto-filled profession
    start_date = models.DateField()
    status = models.CharField(
        max_length=50,
        choices=[
            ('Pending', 'Pending'),
            ('Approved', 'Approved'),
            ('Rejected', 'Rejected'),
        ],
        default='Pending'
    )
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # NEW FIELD: Approved/Rejected By (Who approved or rejected the request)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="approved_work_permits"
    )

    def save(self, *args, **kwargs):
        """ Ensure the profession is auto-filled when the user creates their own work permit. """
        if not self.profession and self.employee.profession:
            self.profession = self.employee.profession
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Work Permit #{self.id} - {self.employee.get_full_name()}"


class HealthSafety(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    date = models.DateField(default=timezone.now)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return self.title


class Workshop(models.Model):
    name = models.CharField(max_length=255)
    date = models.DateField()
    description = models.TextField()
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
