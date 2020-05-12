"""
opengxp.org
Copyright (C) 2019  Henrik Baran

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

# python imports
import os
from pytz import common_timezones
from stat import S_IRUSR

# django imports
from django.utils.translation import gettext_lazy as _
from django.core.management.utils import get_random_secret_key

# crypto imports
from cryptography.fernet import Fernet

# ldap imports
from ldap3 import SIMPLE, AUTO_BIND_TLS_BEFORE_BIND, SUBTREE

###############
# ERROR CODES #
###############

ERROR_NO_RECORD = 0
ERROR_NO_RECORD_PROD = 1
ERROR_NO_RECORD_PROD_VALID = 2

#########
# PATHS #
#########

# base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# directory to store email templates
EMAIL_DIR = os.path.join(BASE_DIR, 'templates')
# security directory for storing secrets in permission controlled files
SECURITY_DIR = os.path.join(BASE_DIR, 'security')
# directory for persistent data storage
DATA_DIR = os.path.join(BASE_DIR, 'data')
# log directory
LOG_DIR = os.path.join(BASE_DIR, 'logs')

###############
# SECRET KEYS #
###############

# secret key
SECRET_KEY_FILE = os.path.join(BASE_DIR, 'forms') + '/keys/secret_key.py'

try:
    from ..keys.secret_key import SECRET_KEY
except ImportError:
    SECRET_KEY = get_random_secret_key()
    with open(SECRET_KEY_FILE, 'w') as file:
        file.write('SECRET_KEY = "{}"'.format(SECRET_KEY))
    os.chmod(SECRET_KEY_FILE, S_IRUSR)

# crypto key
CRYPTO_KEY_FILE = os.path.join(BASE_DIR, 'forms') + '/keys/crypto_key.py'

try:
    from ..keys.crypto_key import CRYPTO_KEY
    CRYPTO_KEY = CRYPTO_KEY.encode('utf-8')
except ImportError:
    CRYPTO_KEY = Fernet.generate_key()
    with open(CRYPTO_KEY_FILE, 'w') as file:
        str_key = str(CRYPTO_KEY, 'utf-8')
        file.write('CRYPTO_KEY = "{}"'.format(str_key))
    os.chmod(CRYPTO_KEY_FILE, S_IRUSR)


###############
# APP DEFAULT #
###############

ALL_PERMISSIONS = '00.00'
DEFAULT_LOG_PASSWORD = 'password'
DEFAULT_LOG_SIGNATURE = 'signature'
DEFAULT_LOG_LOGGING = 'logging'
DEFAULT_LOG_VERIFICATION = 'verification'
DEFAULT_LOG_CONFIRMATIONS = [DEFAULT_LOG_LOGGING,
                             DEFAULT_LOG_SIGNATURE,
                             DEFAULT_LOG_VERIFICATION]
DEFAULT_LOG_QUESTIONS = 'questions'
DEFAULT_SIGNATURE_USER_LOCK = True
DEFAULT_LOG_WF_CIRCULATION = 'circulation'
DEFAULT_LOG_WF_REJECT = 'reject'
DEFAULT_LOG_WF_WORKFLOW = 'workflow'
DEFAULT_RT_NUMBER_RANGE = 0
DEFAULT_PERMISSIONS_PAGINATION_LIMIT = 500
DEFAULT_SYSTEM_USER = 'system'
DEFAULT_SYSTEM_DEVALUE = '--'
DEFAULT_LOG_CREATE = 'create'
DEFAULT_LOG_UPDATE = 'update'
DEFAULT_LOG_DELETE = 'delete'
DEFAULT_LOG_STATUS = 'status'
DEFAULT_LOG_ATTEMPT = 'attempt'
DEFAULT_LOG_LOGIN = 'login'
DEFAULT_LOG_LOGOUT = 'logout'
DEFAULT_FRONT_TIMESTAMP = '%d-%b-%Y %H:%M:%S %Z'
DEFAULT_INITIAL_ROLE = 'all'
DEFAULT_PAGINATION_MAX = 100
DEFAULT_DIALOG_SIGNATURE = DEFAULT_LOG_LOGGING
DEFAULT_DIALOG_COMMENT = 'none'

######################
# REQUEST ATTRIBUTES #
######################

# for check function
ATTR_AUTH = 'CHECK_AUTH'
ATTR_INITIAL_PW = 'CHECK_INITIAL_PW'
ATTR_ROLES = 'CHECK_ROLES'
ATTR_PERMISSION = 'CHECK_PERM'
ATTR_SOD = 'CHECK_SOD'
# others
ATTR_NOW = 'NOW'
ATTR_CASL = 'CASL'

####################
# FLAGS AND VALUES #
####################

CONN_MAX_AGE = None
APPEND_SLASH = False
SILENCED_SYSTEM_CHECKS = ['auth.W004']  # disable warning that username is not unique

####################
# PROFILE DEFAULTS #
####################

PROFILE_TIMEZONES = [zone for zone in common_timezones if zone.startswith('Europe/')]
PROFILE_DEFAULT_TIMEZONE = 'UTC'
SETTINGS_TIMEZONES = [PROFILE_DEFAULT_TIMEZONE] + PROFILE_TIMEZONES
PROFILE_DEFAULT_LANGUAGE = 'en_EN'
PROFILE_DEFAULT_DARKMODE = 'Yes'
PROFILE_DEFAULT_DENSE = 'No'
PROFILE_DEFAULT_PAGINATION_LIMIT = 25
PROFILE_PAGINATION_SELECTIONS = [5, 10, 15, 25, 50, 75, 100]


PROFILE_DATA = [{'key': 'loc.timezone',
                 'default': PROFILE_DEFAULT_TIMEZONE,
                 'human_readable': _('Timezone'),
                 'value': PROFILE_DEFAULT_TIMEZONE},
                {'key': 'loc.language',
                 'default': PROFILE_DEFAULT_LANGUAGE,
                 'human_readable': _('Language'),
                 'value': PROFILE_DEFAULT_LANGUAGE},
                {'key': 'gui.darkmode',
                 'default': PROFILE_DEFAULT_DARKMODE,
                 'human_readable': _('Darkmode'),
                 'value': PROFILE_DEFAULT_DARKMODE},
                {'key': 'gui.dense',
                 'default': PROFILE_DEFAULT_DENSE,
                 'human_readable': _('Dense'),
                 'value': PROFILE_DEFAULT_DENSE},
                {'key': 'gui.pagination',
                 'default': PROFILE_DEFAULT_PAGINATION_LIMIT,
                 'human_readable': _('Pagination limit'),
                 'value': PROFILE_DEFAULT_PAGINATION_LIMIT}]

#################
# LDAP SETTINGS #
#################

LDAP_SERVER_CONNECTION_TIMEOUT = 5
LDAP_CON_VERSION = 3
LDAP_CON_AUTHENTICATE = SIMPLE
LDAP_CON_READ_ONLY = True
LDAP_CON_AUTO_BIN = AUTO_BIND_TLS_BEFORE_BIND
LDAP_SEARCH_SCOPE = SUBTREE

#########
# EMAIL #
#########

EMAIL_SERVER_CONNECTION_TIMEOUT = 5
DEFAULT_EMAIL_SENDER = 'noreply@opengxp.com'
EMAIL_BACKEND = 'urp.backends.Email.MyEmailBackend'

##########################
# APPS MODULES AND SO ON #
##########################

AUTHENTICATION_BACKENDS = [
    'urp.backends.users.external_ldap.MyExternalLDAPUserModelBackend',
    'urp.backends.users.internal_ldap.MyInternalLDAPUserModelBackend',
    'urp.backends.users.internal.MyInternalUserModelBackend',
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

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator', },
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', },
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator', },
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator', },
]


WSGI_APPLICATION = 'forms.wsgi.application'

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'

#####################
# LANGUAGE AND TIME #
#####################

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True
