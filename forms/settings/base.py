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

# basic imports
from basics.custom import value_to_int, value_to_bool, require_file

#########
# PATHS #
#########

# base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# directory to store email templates
EMAIL_DIR = os.path.join(BASE_DIR, 'templates')
# security directory for storing secrets in permission controlled files
SECURITY_DIR = os.path.join(BASE_DIR, 'security')


#########
# EMAIL #
#########

EMAIL_HOST = require_file(path=SECURITY_DIR + '/email/', file_name='HOST')
EMAIL_PORT = int(require_file(path=SECURITY_DIR + '/email/', file_name='PORT'))
EMAIL_HOST_USER = require_file(path=SECURITY_DIR + '/email/', file_name='USER')
EMAIL_HOST_PASSWORD = require_file(path=SECURITY_DIR + '/email/', file_name='PASSWORD')
EMAIL_USE_SSL = True


###############
# APP DEFAULT #
###############

ALL_PERMISSIONS = '00.00'
DEFAULT_LOG_PASSWORD = 'password'
DEFAULT_LOG_QUESTIONS = 'questions'
