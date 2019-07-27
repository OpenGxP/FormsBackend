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

# app imports
from urp.decorators import auth_required
from basics.models import Settings, CHAR_MAX
from basics.custom import get_model_by_string

# rest imports
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status as http_status

# django imports
from django.contrib.auth.password_validation import password_validators_help_texts
from django.db.models.base import ModelBase
from django.core.exceptions import ValidationError


@api_view(['GET'])
@auth_required()
def meta_list(request, dialog):
    # lower all inputs for dialog
    dialog = dialog.lower()
    # filter out status because no public dialog
    if dialog in ['status', 'tokens']:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)
    # determine the model instance from string parameter

    if dialog == 'profile':
        ldap = request.user.ldap
        data = {'get': {},
                'ldap': ldap}
        if not ldap:
            # add calculated field "valid"
            data['get']['valid'] = {'verbose_name': 'Valid',
                                    'data_type': 'CharField',
                                    'render': False,
                                    'format': None}
            # add calculated field "unique"
            data['get']['unique'] = {'verbose_name': 'Unique',
                                     'data_type': 'CharField',
                                     'render': False,
                                     'format': None}

            # add questions fields
            data['get']['question_one'] = {'verbose_name': 'Question one',
                                           'data_type': 'CharField',
                                           'render': True,
                                           'format': None}
            data['get']['question_two'] = {'verbose_name': 'Question two',
                                           'data_type': 'CharField',
                                           'render': True,
                                           'format': None}
            data['get']['question_three'] = {'verbose_name': 'Question three',
                                             'data_type': 'CharField',
                                             'render': True,
                                             'format': None}
        return Response(data=data, status=http_status.HTTP_200_OK)

    try:
        model = get_model_by_string(dialog)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    def get(_request):
        data = {'get': dict(),
                'post': dict()}
        # add get information
        exclude = model.objects.GET_BASE_EXCLUDE + model.objects.GET_MODEL_EXCLUDE
        fields = [i for i in model._meta.get_fields() if i.name not in exclude]
        not_render = model.objects.GET_BASE_NOT_RENDER + model.objects.GET_MODEL_NOT_RENDER
        # add calculated field "valid"
        data['get']['valid'] = {'verbose_name': 'Valid',
                                'data_type': 'CharField',
                                'render': False,
                                'format': None}
        # add calculated field "unique"
        data['get']['unique'] = {'verbose_name': 'Unique',
                                 'data_type': 'CharField',
                                 'render': False,
                                 'format': None}
        for f in fields:
            if f.name in not_render:
                render = False
            else:
                render = True
            # add format for timestamp
            if f.name in ['timtestamp', 'valid_from', 'valid_to']:
                _format = Settings.objects.core_timestamp_format
            else:
                _format = None
            data['get'][f.name] = {'verbose_name': f.verbose_name,
                                   'data_type': f.get_internal_type(),
                                   'render': render,
                                   'format': _format}

        # add post information
        if dialog in ['users', 'roles', 'ldap', 'settings', 'sod', 'email', 'passwords', 'tags', 'spaces', 'lists',
                      'workflows']:
            exclude = model.objects.POST_BASE_EXCLUDE + model.objects.POST_MODEL_EXCLUDE
            fields = [i for i in model._meta.get_fields() if i.name not in exclude]
            for f in fields:
                data['post'][f.name] = {'verbose_name': f.verbose_name,
                                        'help_text': f.help_text,
                                        'max_length': f.max_length,
                                        'data_type': f.get_internal_type(),
                                        'required': not f.blank,
                                        'unique': f.unique,
                                        'lookup': None,
                                        'editable': True}
                if f.name == 'password':
                    data['post'][f.name]['data_type'] = 'PasswordField'

                # create lookup data
                if model.LOOKUP:
                    if f.name in model.LOOKUP:
                        data_model = model.LOOKUP[f.name]['model']
                        if not isinstance(data_model, ModelBase):
                            data['post'][f.name]['lookup'] = {
                                'data': data_model,
                                'multi': model.LOOKUP[f.name]['multi'],
                                'method': model.LOOKUP[f.name]['method']}
                        else:
                            data['post'][f.name]['lookup'] = {
                                'data': data_model.objects.get_by_natural_key_productive_list(
                                    model.LOOKUP[f.name]['key']),
                                'multi': model.LOOKUP[f.name]['multi'],
                                'method': model.LOOKUP[f.name]['method']}

                # settings non-editable field for better visualisation
                if dialog == 'settings' and f.name == 'key':
                    data['post'][f.name]['editable'] = False
                    data['post'][f.name]['required'] = False
                if dialog == 'settings' and f.name == 'default':
                    data['post'][f.name]['editable'] = False
                    data['post'][f.name]['required'] = False

            if dialog == 'users':
                # add calculated field "password_verification"
                data['post']['password_verification'] = {'verbose_name': 'Password verification',
                                                         'help_text': '{}'.format(password_validators_help_texts()),
                                                         'max_length': CHAR_MAX,
                                                         'data_type': 'PasswordField',
                                                         'required': True,
                                                         'unique': False,
                                                         'lookup': None,
                                                         'editable': True}
            if dialog == 'passwords':
                # add calculated fields for manual password reset
                data['post']['password_new'] = {'verbose_name': 'New password',
                                                'help_text': '{}'.format(password_validators_help_texts()),
                                                'max_length': CHAR_MAX,
                                                'data_type': 'PasswordField',
                                                'required': True,
                                                'unique': False,
                                                'lookup': None,
                                                'editable': True}
                data['post']['password_new_verification'] = {'verbose_name': 'New password verification',
                                                             'help_text': '{}'.format(password_validators_help_texts()),
                                                             'max_length': CHAR_MAX,
                                                             'data_type': 'PasswordField',
                                                             'required': True,
                                                             'unique': False,
                                                             'lookup': None,
                                                             'editable': True}
        return Response(data=data, status=http_status.HTTP_200_OK)

    if request.method == 'GET':
        return get(request)
