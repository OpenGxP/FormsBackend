"""
opengxp.org
Copyright (C) 2018  Henrik Baran

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

# ldap imports
from ldap3 import SIMPLE, AUTO_BIND_DEFAULT, SUBTREE

# python imports
import os
from datetime import timedelta

# django imports
from django.core.exceptions import ImproperlyConfigured
from corsheaders.defaults import default_headers


# function for required settings from local files
def require_file(path, file_name):
    """Raise an error if file for configuration not existing or empty. 

        :param path: absolute path to file ending with /
        :type path: str
        :param file_name: file name
        :type file_name: str
        :return: returns string of file content
        :rtype: str
    """
    if not isinstance(path, str) or not isinstance(file_name, str):
        raise TypeError('Argument of type string expected.')
    try:
        with open(path + file_name) as local_file:
            content = local_file.read().strip()
            if content:
                return content
            else:
                raise ImproperlyConfigured('File "{}" is empty.'.format(file_name))
    except FileNotFoundError:
        raise


#################
# LDAP SETTINGS #
#################

LDAP_SERVER_CONNECTION_TIMEOUT = 5
LDAP_CON_VERSION = 3
LDAP_CON_AUTHENTICATE = SIMPLE
LDAP_CON_READ_ONLY = True
LDAP_CON_AUTO_BIN = AUTO_BIND_DEFAULT
LDAP_SEARCH_SCOPE = SUBTREE


########################
# APP SETTINGS DEFAULT #
########################

MAX_LOGIN_ATTEMPTS = 5
DEFAULT_SYSTEM_USER = 'system'
DEFAULT_SYSTEM_DEVALUE = '--'
DEFAULT_LOG_CREATE = 'create'
DEFAULT_LOG_UPDATE = 'update'
DEFAULT_LOG_DELETE = 'delete'
DEFAULT_LOG_STATUS = 'status'
DEFAULT_LOG_ATTEMPT = 'attempt'
DEFAULT_LOG_LOGIN = 'login'
DEFAULT_LOG_LOGOUT = 'logout'

#########
# PATHS #
#########

# base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# security directory for storing secrets in permission controlled files
SECURITY_DIR = os.path.join(BASE_DIR, 'security')


###########
# SECRETS #
###########

# secret keys
SECRET_KEY = require_file(path=SECURITY_DIR + '/keys/', file_name='SECRET_KEY')
SECRET_HASH_KEY = require_file(path=SECURITY_DIR + '/keys/', file_name='SECRET_HASH_KEY')
SECRET_JWT_SIGNING_KEY = require_file(path=SECURITY_DIR + '/keys/', file_name='SECRET_JWT_SIGNING_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
ALLOWED_HOSTS = ['*']
APPEND_SLASH = False
# disable warning that username is not unique
SILENCED_SYSTEM_CHECKS = ['auth.W004']
CSRF_COOKIE_SECURE = False

# Application definition
INSTALLED_APPS = [
    # 'django.contrib.admin',
    'basics.apps.BasicsConfig',
    'urp.apps.UrpConfig',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    # 'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

REST_FRAMEWORK = {
    # Use Django's standard `django.contrib.auth` permissions,
    # or allow read-only access for unauthenticated users.
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'NON_FIELD_ERRORS_KEY': 'validation_errors',
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication'
        # 'rest_framework_simplejwt.authentication.JWTAuthentication',
        # 'rest_framework.authentication.BasicAuthentication',
    ]
}

CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_HEADERS = default_headers + (
    'authentication',
)


AUTHENTICATION_BACKENDS = [
    'urp.backends.MyModelBackend',
    # 'django.contrib.auth.backends.ModelBackend'
]

AUTH_USER_MODEL = 'urp.Users'
LOGIN_URL = '/login'

PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
    'django.contrib.auth.hashers.BCryptPasswordHasher',
]

ROOT_URLCONF = 'forms.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'forms.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}


# Password validation
# https://docs.djangoproject.com/en/1.11/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator', },
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', },
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator', },
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator', },
]


# Internationalization
# https://docs.djangoproject.com/en/1.11/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.11/howto/static-files/

STATIC_URL = '/static/'
