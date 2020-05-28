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

from ldap3.utils.log import BASIC

# import base settings
from .base import *

##############
# THROTTLING #
##############

anon = 10

#################
# LDAP SETTINGS #
#################

LDAP_LOG_LEVEL = BASIC

###############
# APP DEFAULT #
###############

BASE_URL = 'api/'
MAX_LOGIN_ATTEMPTS = 5
DEFAULT_AUTO_LOGOUT = 5  # in minutes
DEFAULT_PASSWORD_RESET_TIME = 5  # in minutes

POSTGRES_USER = require_file(path=SECURITY_DIR + '/credentials/', file_name='POSTGRES_USER')
POSTGRES_PASSWORD = require_file(path=SECURITY_DIR + '/credentials/', file_name='POSTGRES_PASSWORD')


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
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
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
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
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
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_DOMAIN = '{}'.format(require_env('SESSION_COOKIE_DOMAIN'))


############
# DATABASE #
############

# postgres settings
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.environ.get('POSTGRES_DB', 'opengxp'),
        'USER': POSTGRES_USER,
        'PASSWORD': POSTGRES_PASSWORD,
        'HOST': os.environ.get('POSTGRES_HOST', 'localhost'),
        'PORT': os.getenv('POSTGRES_PORT', 5432)
    }
}

####################
# FLAGS AND VALUES #
####################

# general settings
DEBUG = value_to_bool(require_env('DEBUG'))
ALLOWED_HOSTS = ['{}'.format(require_env('ALLOWED_HOSTS'))]
EMAIL_BASE_URL = 'https://{}'.format(ALLOWED_HOSTS[0])

# csrf
CSRF_COOKIE_SECURE = value_to_bool(os.environ.get('CSRF_COOKIE_SECURE', 0))
CSRF_USE_SESSIONS = value_to_bool(os.environ.get('CSRF_USE_SESSIONS', 0))
# CSRF_COOKIE_DOMAIN
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_TRUSTED_ORIGINS = ['{}'.format(os.environ.get('CSRF_TRUSTED_ORIGINS', ''))]

# security
SECURE_CONTENT_TYPE_NOSNIFF = value_to_bool(os.environ.get('SECURE_CONTENT_TYPE_NOSNIFF', 0))
# added via nginx
# SECURE_BROWSER_XSS_FILTER = value_to_bool(os.environ.get('SECURE_BROWSER_XSS_FILTER', 0))
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
                       'rtd.number_range': DEFAULT_RT_NUMBER_RANGE,
                       'api.header.token': DEFAULT_API_HEADER_TOKEN}

###########
# LOGGING #
###########

# logging settings
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'default': {
            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': LOG_DIR + '/default.log',
            'when': 'midnight',
            'formatter': 'standard'
        },
        'request': {
            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': LOG_DIR + '/request.log',
            'when': 'midnight',
            'formatter': 'standard'
        },
        'server': {
            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': LOG_DIR + '/server.log',
            'when': 'midnight',
            'formatter': 'standard'
        },
        'template': {
            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': LOG_DIR + '/template.log',
            'when': 'midnight',
            'formatter': 'standard'
        },
        'db.backends': {
            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': LOG_DIR + '/db_backends.log',
            'when': 'midnight',
            'formatter': 'standard'
        },
        'backends': {
            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': LOG_DIR + '/backends.log',
            'when': 'midnight',
            'formatter': 'standard'
        },
        'security': {
            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': LOG_DIR + '/security.log',
            'when': 'midnight',
            'formatter': 'standard'
        },
        'db.backends.schema': {
            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': LOG_DIR + '/schema.log',
            'when': 'midnight',
            'formatter': 'standard'
        },
        'ldap': {
            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': LOG_DIR + '/ldap.log',
            'when': 'midnight',
            'formatter': 'standard'
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'standard'
        },
    },
    'loggers': {
        'urp.backends': {
            'handlers': ['backends'],
            'level': 'DEBUG',
            'propagate': True
        },
        'ldap3': {
            'handlers': ['ldap'],
            'level': 'DEBUG',
            'propagate': False
        },
        'django.request': {
            'handlers': ['request'],
            'level': 'DEBUG',
            'propagate': False
        },
        'django.template': {
            'handlers': ['template'],
            'level': 'DEBUG',
            'propagate': False
        },
        'django.server': {
            'handlers': ['server'],
            'level': 'DEBUG',
            'propagate': False
        },
        'django.db.backends': {
            'handlers': ['db.backends'],
            'level': 'DEBUG',
            'propagate': False
        },
        'django.security.*': {
            'handlers': ['security'],
            'level': 'DEBUG',
            'propagate': False
        },
        'django.db.backends.schema': {
            'handlers': ['db.backends.schema'],
            'level': 'DEBUG',
            'propagate': False
        }
    }
}
