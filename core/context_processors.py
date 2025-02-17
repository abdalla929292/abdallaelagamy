from django.conf import settings
from .models import CompanySettings
from django.urls import reverse
from django.http import Http404

def company_settings(request):
    try:
        settings = CompanySettings.objects.first()
    except CompanySettings.DoesNotExist:
        settings = None
    return { 'company_settings': settings }

def add_user_roles(request):
    if request.user.is_authenticated:
        return {'user_roles': request.user.roles.all()}
    return {}

def language(request):
    return { 'LANGUAGES': settings.LANGUAGES, 'LANGUAGE_CODE': request.LANGUAGE_CODE, }

def language_paths(request):
    path = request.path
    if path.startswith('/en'):
        en_path = '/ar' + path[3:]
        ar_path = path
    elif path.startswith('/ar'):
        ar_path = '/en' + path[3:]
        en_path = path
    else:
        en_path = '/en' + path
        ar_path = '/ar' + path
    return { 'en_path': en_path, 'ar_path': ar_path, }

def deletion_redirect(request):
    return { 'deletion_redirect_url': reverse('role_list') }
