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

# rest imports
from rest_framework.response import Response
from rest_framework import status as http_status
from rest_framework.decorators import api_view
from rest_framework import serializers

# app imports
from urp.decorators import auth_auth_required
from basics.models import CHAR_DEFAULT
from urp.validators import validate_no_numbers, validate_no_space, validate_no_specials_reduced, validate_only_ascii


def _val_one(value):
    errors = []

    # no spaces
    try:
        validate_no_space(value)
    except serializers.ValidationError as e:
        errors.append(e.detail[0])

    # no numbers
    try:
        validate_no_numbers(value)
    except serializers.ValidationError as e:
        errors.append(e.detail[0])

    # no specials reduced
    try:
        validate_no_specials_reduced(value)
    except serializers.ValidationError as e:
        errors.append(e.detail[0])

    # only ascii for remaining
    try:
        validate_only_ascii(value)
    except serializers.ValidationError as e:
        errors.append(e.detail[0])

    return errors


def _val_ascii(value):
    errors = []

    # only ascii for remaining
    try:
        validate_only_ascii(value)
    except serializers.ValidationError as e:
        errors.append(e.detail)

    return errors


FIELDS_A = ['section', 'field']
FIELDS_B = ['instruction', 'default']


# validate explicitly form data
@api_view(['GET'])
@auth_auth_required()
def validate_form_data(request, key, value):
    # some basic validations
    if not isinstance(key, str):
        raise serializers.ValidationError('Key must be string.')
    if not isinstance(value, str):
        raise serializers.ValidationError('Value must be string.')

    if key not in FIELDS_A + FIELDS_B:
        allowed = ', '.join(FIELDS_A) + ', ' + ', '.join(FIELDS_B)
        raise serializers.ValidationError('Only keys ({}) are supported.'.format(allowed))

    errors = []

    if key in FIELDS_A:
        errors += _val_one(value)

    if key in FIELDS_B:
        errors += _val_ascii(value)

    if len(value) > CHAR_DEFAULT:
        errors.append('Character limit is {}.'.format(CHAR_DEFAULT))

    if errors:
        raise serializers.ValidationError(detail={key: errors})

    return Response(status=http_status.HTTP_200_OK)
