import os
import sys
import locale
from pathlib import Path
from django.utils.translation import gettext_lazy as _

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Ensure UTF-8 is used for translations
if sys.platform.startswith("win"):
    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'a_very_long_and_random_secret_key')

DEBUG = True

ALLOWED_HOSTS = ['*']

# Application definition
INSTALLED_APPS = [
    'modeltranslation',  # Must be before django.contrib.admin
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'core',
    'whitenoise.runserver_nostatic',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # <-- Add this here!
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',  # Must be after session and before common
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

LANGUAGE_COOKIE_NAME = 'django_language'
ROOT_URLCONF = 'Ticket_System.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR / 'core' / 'templates',
            BASE_DIR / 'templates',  # Added for global templates
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.i18n',  # Added for translations
                'core.context_processors.company_settings',
                'core.context_processors.add_user_roles',
                'core.context_processors.language_paths',
                'core.context_processors.language',
                'core.context_processors.deletion_redirect',
            ],
        },
    },
]

WSGI_APPLICATION = 'Ticket_System.wsgi.application'
ASGI_APPLICATION = 'Ticket_System.asgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Internationalization and Localization Settings
USE_I18N = True
USE_L10N = True
USE_TZ = True
TIME_ZONE = 'UTC'

# Language Settings
LANGUAGE_CODE = 'en'
LANGUAGES = (
    ('en', _('English')),
    ('ar', _('Arabic')),
)

# Model Translation Settings
MODELTRANSLATION_DEFAULT_LANGUAGE = 'en'
MODELTRANSLATION_PREPOPULATE_LANGUAGE = 'en'
MODELTRANSLATION_LANGUAGES = ('en', 'ar')
MODELTRANSLATION_FALLBACK_LANGUAGES = ('en', 'ar')

# Locale paths - where Django looks for translation files
LOCALE_PATHS = [
    BASE_DIR / 'locale',
]

# Base directory
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# WhiteNoise settings (for serving static files in Docker)
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Static & Media Files
# Static & Media Files
STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
    os.path.join(BASE_DIR, 'core', 'static'),  # Add this if you have static files inside an app
]
STATIC_ROOT = BASE_DIR / "staticfiles"  # Where collectstatic will place files

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# WhiteNoise settings (for serving static files)
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Custom User Model
AUTH_USER_MODEL = 'core.CustomUser'

# Default Primary Key Type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Authentication & Login Redirects
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'ticket_list'
LOGOUT_REDIRECT_URL = 'login'

# Translation and Locale Settings
MODELTRANSLATION_TRANSLATION_REGISTRY = 'core.translation'

# Fix makemessages Unicode errors by ignoring unnecessary files
IGNORE_FILES = ['requirements.txt', 'README_hyph_*']
LOCALE_ENCODING = 'utf-8'
FILE_CHARSET = 'utf-8'
