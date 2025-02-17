from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from core.models import Role

class Command(BaseCommand):
    help = 'Create default roles (Admin, Manager, Engineer, DCs, Supervisors, Worker, Employee) with associated permissions'

    def handle(self, *args, **options):
        default_roles = [
            {
                "name": "Admin",
                "permissions": [
                    # Ticket permissions
                    "view_ticket", "add_ticket", "change_ticket", "delete_ticket", "assign_ticket", "transfer_ticket",
                    # ITRequest permissions
                    "view_it_request", "add_it_request", "change_it_request", "delete_it_request",
                    # ITWarehouse permissions
                    "view_it_warehouse", "add_it_warehouse", "change_it_warehouse", "delete_it_warehouse",
                    # HRWarehouse permissions
                    "view_hr_warehouse", "add_hr_warehouse", "change_hr_warehouse", "delete_hr_warehouse",
                    # EmployeeDetails permissions
                    "view_employee_details", "add_employee_details", "change_employee_details", "delete_employee_details",
                    # AdministrativeRequest permissions
                    "view_administrative_request", "add_administrative_request", "change_administrative_request", "delete_administrative_request",
                    # FinancialWarehouse permissions
                    "view_financial_warehouse", "add_financial_warehouse", "change_financial_warehouse", "delete_financial_warehouse",
                    # StartWorkPermit permissions
                    "view_start_work_permit", "add_start_work_permit", "change_start_work_permit", "delete_start_work_permit",
                    # CompanyClearance permissions
                    "view_company_clearance", "add_company_clearance", "change_company_clearance", "delete_company_clearance",
                    # Additional full access permissions
                    "view_all_tickets", "view_all_it_requests", "view_all_administrative_requests"
                ],
            },
            {
                "name": "Manager",
                "permissions": [
                    # Managers can view, add, and update (but not necessarily delete) most items.
                    "view_ticket", "add_ticket", "change_ticket",
                    "view_it_request", "add_it_request", "change_it_request",
                    "view_it_warehouse", "add_it_warehouse", "change_it_warehouse",
                    "view_hr_warehouse", "add_hr_warehouse", "change_hr_warehouse",
                    "view_employee_details", "add_employee_details", "change_employee_details",
                    "view_administrative_request", "add_administrative_request", "change_administrative_request",
                    "view_financial_warehouse", "add_financial_warehouse", "change_financial_warehouse",
                    "view_start_work_permit", "add_start_work_permit", "change_start_work_permit",
                    "view_company_clearance", "add_company_clearance", "change_company_clearance",
                    "view_all_tickets", "view_all_it_requests", "view_all_administrative_requests"
                ],
            },
            {
                "name": "Engineer",
                "permissions": [
                    # Engineers can view and add tickets/IT requests.
                    "view_ticket", "add_ticket",
                    "view_it_request", "add_it_request",
                    # And have view-only access on warehouses, employee details, permits, etc.
                    "view_employee_details",
                    "view_it_warehouse",
                    "view_hr_warehouse",
                    "view_administrative_request",
                    "view_financial_warehouse",
                    "view_start_work_permit",
                    "view_company_clearance"
                ],
            },
            {
                "name": "DCs",
                "permissions": [
                    # DCs have similar permissions to Engineers.
                    "view_ticket", "add_ticket",
                    "view_it_request", "add_it_request",
                    "view_employee_details",
                    "view_it_warehouse",
                    "view_hr_warehouse",
                    "view_administrative_request",
                    "view_financial_warehouse",
                    "view_start_work_permit",
                    "view_company_clearance"
                ],
            },
            {
                "name": "Supervisors",
                "permissions": [
                    # Supervisors can view and add tickets/IT requests.
                    "view_ticket", "add_ticket",
                    "view_it_request", "add_it_request",
                    "view_employee_details",
                    "view_it_warehouse",
                    "view_hr_warehouse",
                    "view_administrative_request",
                    # Full Financial Warehouse permissions for Supervisors:
                    "view_financial_warehouse", "add_financial_warehouse", "change_financial_warehouse", "delete_financial_warehouse",
                    "view_start_work_permit",
                    "view_company_clearance"
                ],
            },
            {
                "name": "Worker",
                "permissions": [
                    # Workers have view-only access on all modules.
                    "view_ticket",
                    "view_it_request",
                    "view_employee_details",
                    "view_it_warehouse",
                    "view_hr_warehouse",
                    "view_administrative_request",
                    "view_financial_warehouse",
                    "view_start_work_permit",
                    "view_company_clearance"
                ],
            },
            {
                "name": "Employee",
                "permissions": [
                    # Employees similarly have view-only access.
                    "view_ticket",
                    "view_it_request",
                    "view_employee_details",
                    "view_it_warehouse",
                    "view_hr_warehouse",
                    "view_administrative_request",
                    "view_financial_warehouse",
                    "view_start_work_permit",
                    "view_company_clearance"
                ],
            },
        ]

        for role_data in default_roles:
            role, created = Role.objects.get_or_create(name=role_data["name"])
            permissions_qs = Permission.objects.filter(codename__in=role_data["permissions"])
            count = permissions_qs.count()
            if count == 0:
                self.stdout.write(
                    self.style.WARNING(f'⚠️ No valid permissions found for role: {role_data["name"]}')
                )
                continue

            role.permissions.set(permissions_qs)
            role.save()
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f'✅ Role "{role.name}" created with {count} permissions.')
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS(f'🔄 Role "{role.name}" updated with {count} permissions.')
                )

        self.stdout.write(
            self.style.SUCCESS('🎯 All default roles have been successfully created or updated!')
        )
