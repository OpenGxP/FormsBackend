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
from urp.decorators import auth_auth_required
from urp.models.settings import Settings
from basics.custom import get_model_by_string, meta_lookup

# rest imports
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status as http_status

# django imports
from django.core.exceptions import ValidationError
from django.conf import settings


@api_view(['GET'])
@auth_auth_required()
def meta_list(request, dialog):
    # lower all inputs for dialog
    dialog = dialog.lower()
    # filter out status because no public dialog
    if dialog in ['status', 'tokens']:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)
    # determine the model instance from string parameter

    # meta for timezone dialog
    if dialog == 'set_timezone':
        data = {'post': {}}
        data['post']['value'] = {'verbose_name': 'Timezone',
                                 # 'help_text': 'Allowed timezones: {}.'.format(', '.join(settings.PROFILE_TIMEZONES)),
                                 # 'max_length': 255,
                                 'data_type': 'CharField',
                                 'required': True,
                                 # 'unique': False,
                                 'editable': True,
                                 'lookup': {'data': settings.PROFILE_TIMEZONES,
                                            'multi': False,
                                            'method': 'select'}}

        return Response(data=data, status=http_status.HTTP_200_OK)

    if dialog == 'profile_questions':
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
                'post': dict(),
                'misc': dict(),
                'data': dict()}
        # add get information
        exclude = model.objects.GET_BASE_EXCLUDE + model.objects.GET_MODEL_EXCLUDE
        fields = [i for i in model._meta.get_fields() if i.name not in exclude]
        not_render = model.objects.GET_BASE_NOT_RENDER + model.objects.GET_MODEL_NOT_RENDER
        # add calculated field "valid"
        data['get']['valid'] = {'verbose_name': 'Valid',
                                'data_type': 'CharField',
                                'render': False}
        # add calculated field "unique"
        data['get']['unique'] = {'verbose_name': 'Unique',
                                 'data_type': 'CharField',
                                 'render': False}
        # add calculated field local timestamp if log table
        if model.objects.IS_LOG:
            # FO-220: added localised valid from/to to log meta
            data['get']['valid_from_local'] = {'verbose_name': 'Valid from',
                                               'data_type': 'DateTimeField',
                                               'render': True}
            data['get']['valid_to_local'] = {'verbose_name': 'Valid to',
                                             'data_type': 'DateTimeField',
                                             'render': True}
            data['get']['timestamp_local'] = {'verbose_name': 'Timestamp',
                                              'data_type': 'DateTimeField',
                                              'render': True}
        # FO-215: added exclude for runtime date, because fields are not used for that object type
        if model.objects.HAS_STATUS and not model.objects.IS_RT:
            data['get']['valid_from_local'] = {'verbose_name': 'Valid from',
                                               'data_type': 'DateTimeField',
                                               'render': True}
            data['get']['valid_to_local'] = {'verbose_name': 'Valid to',
                                             'data_type': 'DateTimeField',
                                             'render': True}

        for f in fields:
            if f.name in not_render:
                render = False
            else:
                render = True
            data['get'][f.name] = {'verbose_name': f.verbose_name,
                                   'data_type': f.get_internal_type(),
                                   'render': render}

        # add post information
        if dialog in ['users', 'roles', 'ldap', 'settings', 'sod', 'email', 'passwords', 'tags', 'spaces', 'lists',
                      'workflows', 'profile', 'forms', 'execution']:
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
                meta_lookup(data=data, model=model, f_name=f.name)

                # model specific field properties
                model.objects.meta_field(data, f.name)

                # for unique fields that shall not be updated during life cycle editable must be false
                if f.name == model.UNIQUE:
                    data['post'][f.name]['editable'] = False

            # model specific fields and properties
            model.objects.meta(data)

            # data regarding comment and signature settings
            if dialog not in ['profile']:
                comments = Settings.objects.dialog_comment_dict(dialog)
                signatures = Settings.objects.dialog_signature_dict(dialog)

                for func in comments:
                    data['misc'][func['key']] = {'com': func['value']}

                for func in signatures:
                    data['misc'][func['key']]['sig'] = func['value']

        return Response(data=data, status=http_status.HTTP_200_OK)

    if request.method == 'GET':
        return get(request)
