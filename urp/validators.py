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

# rest imports
from rest_framework.serializers import ValidationError

# python import
import string

# django imports
from django.utils.translation import gettext_lazy as _


##########
# GLOBAL #
##########

SPECIALS = string.punctuation
SPECIALS_REDUCED = string.punctuation.replace('_', '').replace('-', '')


def validate_no_space(value):
    """ Validate no whitespaces for value.

        :param value: input string
        :type value: str

        :return: success flag
        :rtype: bool
    """
    if ' ' in value:
        raise ValidationError(_('Whitespaces are not permitted.'))


def validate_no_specials(value):
    """ Validate no special characters for value.

        :param value: input string
        :type value: str

        :return: success flag
        :rtype: bool
    """
    if any(char in SPECIALS for char in value):
        raise ValidationError(_('Special characters "{}" are not permitted.').format(SPECIALS))


def validate_no_specials_reduced(value):
    """ Validate no special characters for value except "-" and "_".

        :param value: input string
        :type value: str

        :return: success flag
        :rtype: bool
    """
    if any(char in SPECIALS_REDUCED for char in value):
        raise ValidationError(_('Special characters "{}" are not permitted.').format(SPECIALS_REDUCED))


def validate_no_numbers(value):
    if any(char.isdigit() for char in value):
        raise ValidationError(_('Numbers are not permitted.'))


def validate_only_ascii(value):
    try:
        value.encode('ascii')
    except UnicodeEncodeError:
        raise ValidationError(_('Only ascii characters are allowed.'))


def validate_only_positive_numbers(value):
    try:
        if value < 0:
            raise ValidationError(_('Only positive integers are allowed.'))
    except ValueError:
        raise ValidationError(_('Only positive integers are allowed.'))


def validate_last_execution_value(values):
    for x in values:
        # first check if string, then check if empty
        if isinstance(x['value'], str) and x['value'] == '':
            raise ValidationError(_('Not all actual values are completed.'))
        # instance of value is not a bool for None, but is for True / False
        if not isinstance(x['value'], str) and not isinstance(x['value'], bool):
            raise ValidationError(_('Not all actual values are completed.'))
