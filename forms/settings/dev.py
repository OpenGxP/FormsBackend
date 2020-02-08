"""
opengxp.org
Copyright (C) 2020 Henrik Baran

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

# basic imports
from basics.custom import value_to_int, value_to_bool, require_file, require_env

# ldap imports
from ldap3.utils.log import EXTENDED

# python imports
import os

# import base settings
from .base import *

##############
# THROTTLING #
##############

anon = 100

#################
# LDAP SETTINGS #
#################

LDAP_LOG_LEVEL = EXTENDED

###############
# APP DEFAULT #
###############

BASE_URL = ''
MAX_LOGIN_ATTEMPTS = 15
DEFAULT_AUTO_LOGOUT = 15  # in minutes
DEFAULT_PASSWORD_RESET_TIME = 60  # in minutes

##########################
# APPS MODULES AND SO ON #
##########################

# Application definition
INSTALLED_APPS = [
    'basics.apps.BasicsConfig',
    'urp.apps.UrpConfig',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
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
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'NON_FIELD_ERRORS_KEY': 'validation_errors',
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication'
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '{}/min'.format(anon)
    }
}

#########
# CACHE #
#########

if os.environ.get('CACHE', 0):
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": "redis://{}:6379/0".format(os.environ.get('REDIS_HOST', 'redis')),
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
                "COMPRESSOR": "django_redis.compressors.zlib.ZlibCompressor",
            }
        }
    }

SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = value_to_bool(os.environ.get('SESSION_COOKIE_HTTPONLY', 1))
SESSION_COOKIE_SECURE = value_to_bool(os.environ.get('SESSION_COOKIE_SECURE', 0))
# SESSION_COOKIE_DOMAIN
SESSION_COOKIE_SAMESITE = None


############
# DATABASE #
############

# sqlite settings
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(DATA_DIR, 'db.sqlite3'),
    }
}

####################
# FLAGS AND VALUES #
####################

# general settings
DEBUG = True
ALLOWED_HOSTS = ['*']
EMAIL_BASE_URL = 'http://127.0.0.1:8000'

# csrf
CSRF_COOKIE_SECURE = value_to_bool(os.environ.get('CSRF_COOKIE_SECURE', 0))
CSRF_USE_SESSIONS = value_to_bool(os.environ.get('CSRF_USE_SESSIONS', 0))
# CSRF_COOKIE_DOMAIN
CSRF_COOKIE_SAMESITE = None
CSRF_TRUSTED_ORIGINS = []

# security
SECURE_CONTENT_TYPE_NOSNIFF = value_to_bool(os.environ.get('SECURE_CONTENT_TYPE_NOSNIFF', 0))
SECURE_BROWSER_XSS_FILTER = value_to_bool(os.environ.get('SECURE_BROWSER_XSS_FILTER', 0))
SECURE_HSTS_INCLUDE_SUBDOMAINS = value_to_bool(os.environ.get('SECURE_HSTS_INCLUDE_SUBDOMAINS', 0))
SECURE_SSL_REDIRECT = value_to_bool(os.environ.get('SECURE_SSL_REDIRECT', 0))
SECURE_HSTS_PRELOAD = value_to_bool(os.environ.get('SECURE_HSTS_PRELOAD', 0))

# security settings of type integer
SECURE_HSTS_SECONDS = value_to_int(os.environ.get('SECURE_HSTS_SECONDS', 0))
SESSION_COOKIE_AGE = value_to_int(os.environ.get('SESSION_COOKIE_AGE', 3600))


# security settings of type tuple
if os.environ.get('SECURE_PROXY_SSL_HEADER', 0):
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# security settings of type string
X_FRAME_OPTIONS = os.environ.get('X_FRAME_OPTIONS', 'SAMEORIGIN')

# cors
CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_CREDENTIALS = True
CORS_ORIGIN_WHITELIST = (
    os.environ.get('CORS_ORIGIN_WHITELIST', '')
)

###################
# CUSTOM SETTINGS #
###################

INITIALIZE_SETTINGS = {'auth.max_login_attempts': MAX_LOGIN_ATTEMPTS,
                       'core.system_username': DEFAULT_SYSTEM_USER,
                       'core.devalue': DEFAULT_SYSTEM_DEVALUE,
                       'core.timestamp_format': DEFAULT_FRONT_TIMESTAMP,
                       'core.auto_logout': DEFAULT_AUTO_LOGOUT,
                       'core.password_reset_time': DEFAULT_PASSWORD_RESET_TIME,
                       'email.sender': DEFAULT_EMAIL_SENDER,
                       'core.initial_role': DEFAULT_INITIAL_ROLE,
                       'profile.default.timezone': PROFILE_DEFAULT_TIMEZONE,
                       'rtd.number_range': DEFAULT_RT_NUMBER_RANGE}
