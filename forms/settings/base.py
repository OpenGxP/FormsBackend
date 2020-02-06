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

####################
# PROFILE DEFAULTS #
####################

PROFILE_TIMEZONES = [zone for zone in common_timezones if zone.startswith('Europe/')]
PROFILE_DEFAULT_TIMEZONE = 'UTC'
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
