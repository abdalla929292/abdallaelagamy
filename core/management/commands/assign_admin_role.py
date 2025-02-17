# core/management/commands/assign_admin_role.py

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from core.models import Role

class Command(BaseCommand):
    help = 'Assign Admin role to a specified user'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='Username of the user to assign the Admin role')

    def handle(self, *args, **options):
        username = options['username']
        User = get_user_model()
        try:
            user = User.objects.get(username=username)
            admin_role, created = Role.objects.get_or_create(name='Admin')
            user.roles.add(admin_role)
            user.save()
            self.stdout.write(self.style.SUCCESS(f'Admin role assigned to {username} successfully!'))
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'User {username} does not exist'))
