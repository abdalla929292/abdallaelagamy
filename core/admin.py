from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Permission
from .forms import CustomUserCreationForm, CustomUserUpdateForm
from .models import CustomUser, Role, Position, Department, RequestType, Ticket, CompanySettings, SubRequestType, SubPosition


class TicketAdmin(admin.ModelAdmin):
    """ Ticket Admin Panel with Role-Based Filtering """
    list_display = ('id', 'title', 'status', 'get_applied_by', 'get_assigned_to')  # ✅ Fixed references
    list_filter = ('status', 'applied_by', 'assigned_to')  # ✅ Updated to use applied_by
    search_fields = ('title', 'applied_by__username', 'assigned_to__username')

    def get_queryset(self, request):
        """ Restrict employees to only see their own tickets """
        qs = super().get_queryset(request)
        if request.user.is_superuser or request.user.roles.filter(name__in=["Admin", "Manager", "General Manager"]).exists():
            return qs  # Show all tickets to Admins, Managers, and GMs
        return qs.filter(applied_by=request.user)  # Employees see only their own tickets

    def get_applied_by(self, obj):
        """ Show Applied By in the Admin Panel """
        return obj.applied_by.username if obj.applied_by else "N/A"
    get_applied_by.short_description = "Applied By"

    def get_assigned_to(self, obj):
        """ Show Assigned To in the Admin Panel """
        return obj.assigned_to.username if obj.assigned_to else "N/A"
    get_assigned_to.short_description = "Assigned To"

admin.site.register(Ticket, TicketAdmin)


class UserAdmin(BaseUserAdmin):
    """ Custom User Admin Panel with Role Filtering """
    add_form = CustomUserCreationForm
    form = CustomUserUpdateForm
    model = CustomUser

    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'is_active', 'position', 'get_roles')
    list_filter = ('is_staff', 'is_active', 'roles')
    search_fields = ('email', 'username')
    ordering = ('email',)

    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'position', 'roles')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'groups', 'user_permissions')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'first_name', 'last_name', 'position', 'roles', 'is_staff', 'is_active')}),
    )

    def get_roles(self, obj):
        """ Display assigned roles in Admin Panel """
        return ", ".join([role.name for role in obj.roles.all()])
    get_roles.short_description = "Roles"

admin.site.register(CustomUser, UserAdmin)


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    """ Role Management with Auto Permissions Assignment """
    list_display = ['name']
    search_fields = ['name']

    def save_model(self, request, obj, form, change):
        """ Assign default permissions when a role is created """
        super().save_model(request, obj, form, change)
        if not change:
            default_permissions = [
                'view_ticket', 'add_ticket', 'change_ticket', 'delete_ticket'
            ]
            permissions = Permission.objects.filter(codename__in=default_permissions)
            obj.permissions.set(permissions)

# Register Other Models
admin.site.register(Position)
admin.site.register(Department)
admin.site.register(RequestType)
admin.site.register(SubRequestType)
admin.site.register(CompanySettings)
admin.site.register(SubPosition)
