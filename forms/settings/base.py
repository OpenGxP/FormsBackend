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

# basic imports
from basics.custom import value_to_int, value_to_bool, require_file

# django imports
from django.utils.translation import gettext_lazy as _

#########
# PATHS #
#########

# base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# directory to store email templates
EMAIL_DIR = os.path.join(BASE_DIR, 'templates')
# security directory for storing secrets in permission controlled files
SECURITY_DIR = os.path.join(BASE_DIR, 'security')


###############
# APP DEFAULT #
###############

ALL_PERMISSIONS = '00.00'
DEFAULT_LOG_PASSWORD = 'password'
DEFAULT_LOG_QUESTIONS = 'questions'
CRYPTO_KEY = 'CRYPTO_KEY'

####################
# PROFILE DEFAULTS #
####################

PROFILE_TIMEZONES = [zone for zone in common_timezones if zone.startswith('Europe/')]
PROFILE_DEFAULT_TIMEZONE = 'UTC'
PROFILE_DEFAULT_LANGUAGE = 'en_EN'
PROFILE_DEFAULT_DARKMODE = 'Yes'
PROFILE_DEFAULT_DENSE = 'No'
PROFILE_DEFAULT_PAGINATION_LIMIT = 25


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
