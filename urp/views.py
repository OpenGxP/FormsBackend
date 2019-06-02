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

# python imports
from functools import wraps

# rest imports
from rest_framework.response import Response
from rest_framework import status as http_status
from rest_framework.decorators import api_view
from rest_framework.reverse import reverse
from rest_framework import serializers

# custom imports
from .models import Status, Roles, Permissions, Users, AccessLog, PermissionsLog, RolesLog, UsersLog, LDAP, LDAPLog, \
    SoD, SoDLog, Vault
from .serializers import StatusReadWriteSerializer, PermissionsReadWriteSerializer, RolesReadSerializer, \
    RolesWriteSerializer, UsersReadSerializer, RolesDeleteStatusSerializer, RolesNewVersionSerializer, \
    UsersWriteSerializer, UsersNewVersionSerializer, UsersDeleteStatusSerializer, \
    AccessLogReadWriteSerializer, CentralLogReadWriteSerializer, StatusLogReadSerializer, \
    PermissionsLogReadSerializer, RolesLogReadSerializer, UsersLogReadSerializer, AUDIT_TRAIL_SERIALIZERS, \
    LDAPLogReadSerializer, LDAPReadWriteSerializer, LDAPDeleteSerializer, SettingsLogReadSerializer, \
    SettingsReadWriteSerializer, SoDLogReadSerializer, SoDDeleteStatusNewVersionSerializer, SoDWriteSerializer, \
    SoDReadSerializer, UsersPassword
from .decorators import perm_required, auth_required
from basics.models import StatusLog, CentralLog, SettingsLog, Settings, CHAR_MAX
from basics.custom import get_model_by_string
from .backends import write_access_log
from .vault import validate_password_input, update_vault_record

# django imports
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
from django.conf import settings
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie, csrf_exempt
from django.middleware.csrf import get_token
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import password_validators_help_texts


###############
# AUTO_LOGOUT #
###############

def refresh_time(request, active=True):
    now = timezone.now()
    if now - request.session['last_touch'] > timezone.timedelta(minutes=Settings.objects.core_auto_logout):
        data = {
            'user': request.user.username,
            'timestamp': now,
            'mode': 'automatic',
            'method': Settings.objects.core_devalue,
            'action': settings.DEFAULT_LOG_LOGOUT,
            'attempt': Settings.objects.core_devalue,
            'active': Settings.objects.core_devalue
        }
        logout(request)
        if request.user.is_anonymous:
            write_access_log(data)
    else:
        # only refresh if user was active (default for request)
        if active:
            request.session['last_touch'] = now
        return True


def auto_logout():
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # use method
            if refresh_time(request=request):
                return view_func(request, *args, **kwargs)
            else:
                return Response(status=http_status.HTTP_401_UNAUTHORIZED)
        return wrapper
    return decorator


@api_view(['PATCH'])
@auth_required()
def logout_auto_view(request):
    if not hasattr(request, 'data'):
        raise serializers.ValidationError('Field "active" required.')
    if 'active' not in request.data:
        raise serializers.ValidationError('Field "active" required.')
    active = request.data['active']
    if not isinstance(active, bool):
        raise serializers.ValidationError('Data type bool required for field "active".')
    if refresh_time(request=request, active=active):
        return Response(status=http_status.HTTP_200_OK)
    else:
        return Response(status=http_status.HTTP_401_UNAUTHORIZED)


########
# ROOT #
########

@api_view(['GET'])
def api_root(request):
    root = {'base': {'root': '/',
                     'subjects': {'login': {'url': reverse('login-view', request=request)},
                                  'csrftoken': {'url': reverse('get_csrf_token', request=request)},
                                  'logout': {'url': reverse('logout-view', request=request)}}},
            'administration': {'root': '/admin/',
                               'subjects': {'status': {'url': reverse('status-list', request=request)},
                                            'permissions': {'url': reverse('permissions-list', request=request)},
                                            'roles': {'url': reverse('roles-list', request=request)},
                                            'ldap': {'url': reverse('ldap-list', request=request)},
                                            'users': {'url': reverse('users-list', request=request)},
                                            'users_password': {'url': reverse('users-password-list', request=request)},
                                            'sod': {'url': reverse('sod-list', request=request)},
                                            'settings': {'url': reverse('settings-list', request=request)}}},
            'logs': {'root': '/logs/',
                     'subjects': {'central': {'url': reverse('central-log-list', request=request)},
                                  'access': {'url': reverse('access-log-list', request=request)},
                                  'status': {'url': reverse('status-log-list', request=request)},
                                  'permissions': {'url': reverse('permissions-log-list', request=request)},
                                  'roles': {'url': reverse('roles-log-list', request=request)},
                                  'ldap': {'url': reverse('ldap-log-list', request=request)},
                                  'users': {'url': reverse('users-log-list', request=request)},
                                  'sod': {'url': reverse('sod-log-list', request=request)},
                                  'settings': {'url': reverse('settings-log-list', request=request)}}}}

    return Response(root)


#########
# LOGIN #
#########

@api_view(['POST'])
@csrf_exempt
def login_view(request):
    # FO-137: adapted validation properly and raise serializer validation error (including 400 response)
    if not hasattr(request, 'data'):
        raise serializers.ValidationError('Fields "{}" and "password" are required.'.format(Users.USERNAME_FIELD))
    if Users.USERNAME_FIELD in request.data and 'password' in request.data:
        # FO-137: adapted validation properly and raise serializer validation error (including 400 response)
        if not isinstance(request.data['username'], str) or not isinstance(request.data['password'], str):
            raise serializers.ValidationError('Fields "{}" and "password" must be strings.'
                                              .format(Users.USERNAME_FIELD))
        # authenticate user
        user = authenticate(request=request, username=request.data['username'], password=request.data['password'])
    else:
        # FO-137: raise serializer validation error (including 400 response)
        raise serializers.ValidationError('Fields "{}" and "password" are required.'.format(Users.USERNAME_FIELD))
    if user:
        login(request, user)
        request.session['last_touch'] = timezone.now()
        # pass authenticated user roles to casl method, split to parse
        casl = Roles.objects.casl(user.roles.split(','))
        return Response(casl, status=http_status.HTTP_200_OK)
    else:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)


###################
# PASSWORD_CHANGE #
###################

@api_view(['PATCH'])
@auth_required()
@perm_required('{}.13'.format(Vault.MODEL_ID))
@csrf_protect
def change_password_view(request, username):
    if not hasattr(request, 'data'):
        raise serializers.ValidationError('Fields "password" and "password_two" are required.')
    try:
        vault = Vault.objects.get(username=username)
    except Vault.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    validate_password_input(request.data)

    raw_pw = request.data['password']
    data = dict()
    data['password'] = make_password(raw_pw)
    data['initial_password'] = True
    update_vault_record(data=data, instance=vault, action=settings.DEFAULT_LOG_PASSWORD, user=request.user.username)

    return Response(status=http_status.HTTP_200_OK)


########
# CSRF #
########

@api_view(['GET'])
@auth_required()
def get_csrf_token(request):
    token = {settings.CSRF_COOKIE_NAME: get_token(request)}
    return Response(data=token, status=http_status.HTTP_200_OK)


##########
# LOGOUT #
##########

@api_view(['GET'])
@auth_required()
def logout_view(request):
    data = {
        'user': request.user.username,
        'timestamp': timezone.now(),
        'mode': 'manual',
        'method': Settings.objects.core_devalue,
        'action': settings.DEFAULT_LOG_LOGOUT,
        'attempt': Settings.objects.core_devalue,
        'active': Settings.objects.core_devalue
    }
    logout(request)
    if request.user.is_anonymous:
        write_access_log(data)
        return Response(status=http_status.HTTP_200_OK)
    else:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)


##########
# STATUS #
##########

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('01.01')
def status_list(request):
    """
    List all status.
    """
    stat = Status.objects.all()
    serializer = StatusReadWriteSerializer(stat, many=True)
    return Response(serializer.data)


#############
# STATUSLOG #
#############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('07.01')
def status_log_list(request):
    """
    List all status log records.
    """
    logs = StatusLog.objects.all()
    serializer = StatusLogReadSerializer(logs, many=True)
    return Response(serializer.data)


###############
# PERMISSIONS #
###############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('02.01')
def permissions_list(request):
    """
    List all permissions.
    """
    perm = Permissions.objects.all()
    serializer = PermissionsReadWriteSerializer(perm, many=True)
    return Response(serializer.data)


##################
# PERMISSIONSLOG #
##################

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('08.01')
def permissions_log_list(request):
    """
    List all permissions log records.
    """
    logs = PermissionsLog.objects.all()
    serializer = PermissionsLogReadSerializer(logs, many=True)
    return Response(serializer.data)


###############
# SETTINGSLOG #
###############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(SettingsLog.MODEL_ID))
def settings_log_list(request):
    """
    List all settings log records.
    """
    logs = SettingsLog.objects.all()
    serializer = SettingsLogReadSerializer(logs, many=True)
    return Response(serializer.data)


############
# SETTINGS #
############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@ensure_csrf_cookie
@perm_required('{}.01'.format(Settings.MODEL_ID))
def settings_list(request):
    """
    List all settings records.
    """
    query = Settings.objects.all()
    serializer = SettingsReadWriteSerializer(query, many=True)
    return Response(serializer.data)


# GET detail
@api_view(['GET', 'PATCH'])
@auth_required()
@auto_logout()
def settings_detail(request, key):
    @perm_required('{}.03'.format(Settings.MODEL_ID))
    @csrf_protect
    def patch(_request):
        _serializer = SettingsReadWriteSerializer(query, data=_request.data, context={'method': 'PATCH',
                                                                                      'function': '',
                                                                                      'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(Settings.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        serializer = SettingsReadWriteSerializer(query)
        return Response(serializer.data)

    try:
        query = Settings.objects.get(key=key)
    except Settings.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)


###########
# LDAPLOG #
###########

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(LDAPLog.MODEL_ID))
def ldap_log_list(request):
    """
    List all ldap log records.
    """
    logs = LDAPLog.objects.all()
    serializer = LDAPLogReadSerializer(logs, many=True)
    return Response(serializer.data)


########
# LDAP #
########

# GET list
@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def ldap_list(request):
    @perm_required('{}.02'.format(LDAP.MODEL_ID))
    @csrf_protect
    def post(_request):
        _serializer = LDAPReadWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                           'function': 'new',
                                                                           'user': request.user.username})

        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(LDAP.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        query = LDAP.objects.all()
        serializer = LDAPReadWriteSerializer(query, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


# GET detail
@api_view(['GET', 'PATCH', 'DELETE'])
@auth_required()
@auto_logout()
def ldap_detail(request, host):
    @perm_required('{}.03'.format(LDAP.MODEL_ID))
    @csrf_protect
    def patch(_request):
        _serializer = LDAPReadWriteSerializer(query, data=_request.data, context={'method': 'PATCH',
                                                                                  'function': '',
                                                                                  'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.04'.format(LDAP.MODEL_ID))
    @csrf_protect
    def delete(_request):
        _serializer = LDAPDeleteSerializer(query, data={}, context={'method': 'DELETE',
                                                                    'function': '',
                                                                    'user': request.user.username})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(LDAP.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        serializer = LDAPReadWriteSerializer(query)
        return Response(serializer.data)

    try:
        query = LDAP.objects.get(host=host)
    except LDAP.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)

    elif request.method == 'DELETE':
        return delete(request)


##############
# CENTRALLOG #
##############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('06.01')
def central_log_list(request):
    logs = CentralLog.objects.all()
    serializer = CentralLogReadWriteSerializer(logs, many=True)
    return Response(serializer.data)


#############
# ACCESSLOG #
#############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('05.01')
def access_log_list(request):
    logs = AccessLog.objects.all()
    serializer = AccessLogReadWriteSerializer(logs, many=True)
    return Response(serializer.data)


###############
# AUDIT_TRAIL #
###############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
def audit_trail_list(request, dialog, lifecycle_id):
    # lower all inputs for dialog
    dialog = dialog.lower()
    # determine the model instance from string parameter
    try:
        model = get_model_by_string(dialog).objects.LOG_TABLE
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(model.MODEL_ID))
    def get(_request):
        # check if at least one record exists
        try:
            record = model.objects.filter(lifecycle_id=lifecycle_id).get()
            serializer = AUDIT_TRAIL_SERIALIZERS[dialog](record)
        # no record exists for that lifecycle_id
        except model.DoesNotExist:
            return Response(status=http_status.HTTP_404_NOT_FOUND)
        # not a valid lifecycle_id
        except ValidationError:
            return Response(status=http_status.HTTP_400_BAD_REQUEST)
        # lifecycle_id ok and multiple records, no error
        except model.MultipleObjectsReturned:
            records = model.objects.filter(lifecycle_id=lifecycle_id).all()
            serializer = AUDIT_TRAIL_SERIALIZERS[dialog](records, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)


#################
# USERSPASSWORD #
#################

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@ensure_csrf_cookie
@perm_required('{}.01'.format(Vault.MODEL_ID))
def users_password_list(request):
    users = Vault.objects.all()
    serializer = UsersPassword(users, many=True)
    return Response(serializer.data)


########
# META #
########

@api_view(['GET'])
@auth_required()
def meta_list(request, dialog):
    # lower all inputs for dialog
    dialog = dialog.lower()
    # filter out status because no public dialog
    if dialog in ['status']:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)
    # determine the model instance from string parameter
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
        if dialog in ['users', 'roles', 'ldap', 'settings', 'sod']:
            exclude = model.objects.POST_BASE_EXCLUDE + model.objects.POST_MODEL_EXCLUDE
            fields = [i for i in model._meta.get_fields() if i.name not in exclude]
            for f in fields:
                data['post'][f.name] = {'verbose_name': f.verbose_name,
                                        'help_text': f.help_text,
                                        'max_length': f.max_length,
                                        'data_type': f.get_internal_type(),
                                        'required': not f.blank,
                                        'unique': f.unique}
            if dialog == 'users':
                # add calculated field "password_two"
                data['post']['password_two'] = {'verbose_name': 'Password verification',
                                                'help_text': '{}'.format(password_validators_help_texts()),
                                                'max_length': CHAR_MAX,
                                                'data_type': 'CharField',
                                                'required': True,
                                                'unique': False}
        return Response(data=data, status=http_status.HTTP_200_OK)

    if request.method == 'GET':
        return get(request)


#########
# ROLES #
#########

# GET list
@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def roles_list(request):
    """
    List all roles.
    """

    @perm_required('03.02')
    @csrf_protect
    def post(_request):
        # add version for new objects because of combined unique constraint
        _request.data['version'] = 1
        _serializer = RolesWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                        'function': 'new',
                                                                        'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('03.01')
    @ensure_csrf_cookie
    def get(_request):
        roles = Roles.objects.all()
        serializer = RolesReadSerializer(roles, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


# GET detail
@api_view(['GET', 'PATCH', 'POST', 'DELETE'])
@auth_required()
@auto_logout()
def roles_detail(request, lifecycle_id, version):
    """
    Retrieve roles.
    """

    @perm_required('03.03')
    @csrf_protect
    def patch(_request):
        _serializer = RolesWriteSerializer(role, data=_request.data, context={'method': 'PATCH',
                                                                              'function': '',
                                                                              'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @csrf_protect
    def post_base(_request):
        _serializer = RolesNewVersionSerializer(role, data=_request.data, context={'method': 'POST',
                                                                                   'function': 'new_version',
                                                                                   'user': request.user.username})
        if _serializer.is_valid():
            _serializer.create(validated_data=_serializer.validated_data)
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('03.11')
    def post(_request):
        return post_base(_request)

    @perm_required('03.12')
    def post_archived(_request):
        return post_base(_request)

    @perm_required('03.04')
    @csrf_protect
    def delete(_request):
        _serializer = RolesDeleteStatusSerializer(role, data={}, context={'method': 'DELETE',
                                                                          'function': '',
                                                                          'user': request.user.username})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('03.01')
    @ensure_csrf_cookie
    def get(_request):
        serializer = RolesReadSerializer(role)
        return Response(serializer.data)

    try:
        role = Roles.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Roles.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)

    elif request.method == 'POST':
        if role.status.id == Status.objects.archived:
            return post_archived(request)
        else:
            return post(request)

    elif request.method == 'DELETE':
        return delete(request)


@api_view(['PATCH'])
@auth_required()
@auto_logout()
def roles_status(request, lifecycle_id, version, status):
    @csrf_protect
    def patch_base(_request):
        _serializer = RolesDeleteStatusSerializer(role, data={}, context={'method': 'PATCH',
                                                                          'function': 'status_change',
                                                                          'status': status,
                                                                          'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('03.05')
    def patch_circulation(_request):
        return patch_base(_request)

    @perm_required('03.06')
    def patch_draft(_request):
        return patch_base(_request)

    @perm_required('03.07')
    def patch_productive(_request):
        return patch_base(_request)

    @perm_required('03.08')
    def patch_blocked(_request):
        return patch_base(_request)

    @perm_required('03.09')
    def patch_archived(_request):
        return patch_base(_request)

    @perm_required('03.10')
    def patch_inactive(_request):
        return patch_base(_request)

    try:
        role = Roles.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Roles.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'PATCH':
        if status == 'circulation':
            return patch_circulation(request)
        if status == 'draft':
            return patch_draft(request)
        if status == 'productive':
            return patch_productive(request)
        if status == 'blocked':
            return patch_blocked(request)
        if status == 'archived':
            return patch_archived(request)
        if status == 'inactive':
            return patch_inactive(request)
        return patch_base(request)


############
# ROLESLOG #
############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('09.01')
def roles_log_list(request):
    """
    List all roles log records.
    """
    logs = RolesLog.objects.all()
    serializer = RolesLogReadSerializer(logs, many=True)
    return Response(serializer.data)


#########
# USERS #
#########

# GET list
@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def users_list(request):
    @perm_required('04.02')
    @csrf_protect
    def post(_request):
        # add version for new objects because of combined unique constraint
        _request.data['version'] = 1
        _serializer = UsersWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                        'function': 'new',
                                                                        'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('04.01')
    @ensure_csrf_cookie
    def get(_request):
        users = Users.objects.all()
        serializer = UsersReadSerializer(users, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


# GET detail
@api_view(['GET', 'PATCH', 'POST', 'DELETE'])
@auth_required()
@auto_logout()
def users_detail(request, lifecycle_id, version):
    @perm_required('04.03')
    @csrf_protect
    def patch(_request):
        _serializer = UsersWriteSerializer(user, data=_request.data, context={'method': 'PATCH',
                                                                              'function': '',
                                                                              'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('04.01')
    @ensure_csrf_cookie
    def get(_request):
        serializer = UsersReadSerializer(user)
        return Response(serializer.data)

    @csrf_protect
    def post_base(_request):
        _serializer = UsersNewVersionSerializer(user, data=_request.data, context={'method': 'POST',
                                                                                   'function': 'new_version',
                                                                                   'user': request.user.username})
        if _serializer.is_valid():
            _serializer.create(validated_data=_serializer.validated_data)
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('04.11')
    def post(_request):
        return post_base(_request)

    @perm_required('04.12')
    def post_archived(_request):
        return post_base(_request)

    @perm_required('04.04')
    @csrf_protect
    def delete(_request):
        _serializer = UsersDeleteStatusSerializer(user, data={}, context={'method': 'DELETE',
                                                                          'function': '',
                                                                          'user': request.user.username})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    try:
        user = Users.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Users.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)

    elif request.method == 'POST':
        if user.status.id == Status.objects.archived:
            return post_archived(request)
        else:
            return post(request)

    elif request.method == 'DELETE':
        return delete(request)


@api_view(['PATCH'])
@auth_required()
@auto_logout()
def users_status(request, lifecycle_id, version, status):
    @csrf_protect
    def patch_base(_request):
        _serializer = UsersDeleteStatusSerializer(user, data={}, context={'method': 'PATCH',
                                                                          'function': 'status_change',
                                                                          'status': status,
                                                                          'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('04.05')
    def patch_circulation(_request):
        return patch_base(_request)

    @perm_required('04.06')
    def patch_draft(_request):
        return patch_base(_request)

    @perm_required('04.07')
    def patch_productive(_request):
        return patch_base(_request)

    @perm_required('04.08')
    def patch_blocked(_request):
        return patch_base(_request)

    @perm_required('04.09')
    def patch_archived(_request):
        return patch_base(_request)

    @perm_required('04.10')
    def patch_inactive(_request):
        return patch_base(_request)

    try:
        user = Users.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Users.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'PATCH':
        if status == 'circulation':
            return patch_circulation(request)
        if status == 'draft':
            return patch_draft(request)
        if status == 'productive':
            return patch_productive(request)
        if status == 'blocked':
            return patch_blocked(request)
        if status == 'archived':
            return patch_archived(request)
        if status == 'inactive':
            return patch_inactive(request)
        return patch_base(request)


############
# USERSLOG #
############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('10.01')
def users_log_list(request):
    """
    List all users log records.
    """
    logs = UsersLog.objects.all()
    serializer = UsersLogReadSerializer(logs, many=True)
    return Response(serializer.data)


#######
# SOD #
#######

# GET list
@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def sod_list(request):
    @perm_required('{}.02'.format(SoD.MODEL_ID))
    @csrf_protect
    def post(_request):
        # add version for new objects because of combined unique constraint
        _request.data['version'] = 1
        _serializer = SoDWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                      'function': 'new',
                                                                      'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(SoD.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        roles = SoD.objects.all()
        serializer = SoDReadSerializer(roles, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


# GET detail
@api_view(['GET', 'PATCH', 'POST', 'DELETE'])
@auth_required()
@auto_logout()
def sod_detail(request, lifecycle_id, version):
    @perm_required('{}.03'.format(SoD.MODEL_ID))
    @csrf_protect
    def patch(_request):
        _serializer = SoDWriteSerializer(role, data=_request.data, context={'method': 'PATCH',
                                                                            'function': '',
                                                                            'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @csrf_protect
    def post_base(_request):
        _serializer = SoDDeleteStatusNewVersionSerializer(role, data=_request.data,
                                                          context={'method': 'POST',
                                                                   'function': 'new_version',
                                                                   'user': request.user.username})
        if _serializer.is_valid():
            _serializer.create(validated_data=_serializer.validated_data)
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.11'.format(SoD.MODEL_ID))
    def post(_request):
        return post_base(_request)

    @perm_required('{}.12'.format(SoD.MODEL_ID))
    def post_archived(_request):
        return post_base(_request)

    @perm_required('{}.04'.format(SoD.MODEL_ID))
    @csrf_protect
    def delete(_request):
        _serializer = SoDDeleteStatusNewVersionSerializer(role, data={}, context={'method': 'DELETE',
                                                                                  'function': '',
                                                                                  'user': request.user.username})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(SoD.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        serializer = SoDReadSerializer(role)
        return Response(serializer.data)

    try:
        role = SoD.objects.get(lifecycle_id=lifecycle_id, version=version)
    except SoD.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)

    elif request.method == 'POST':
        if role.status.id == Status.objects.archived:
            return post_archived(request)
        else:
            return post(request)

    elif request.method == 'DELETE':
        return delete(request)


@api_view(['PATCH'])
@auth_required()
@auto_logout()
def sod_status(request, lifecycle_id, version, status):
    @csrf_protect
    def patch_base(_request):
        _serializer = SoDDeleteStatusNewVersionSerializer(role, data={}, context={'method': 'PATCH',
                                                                                  'function': 'status_change',
                                                                                  'status': status,
                                                                                  'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.05'.format(SoD.MODEL_ID))
    def patch_circulation(_request):
        return patch_base(_request)

    @perm_required('{}.06'.format(SoD.MODEL_ID))
    def patch_draft(_request):
        return patch_base(_request)

    @perm_required('{}.07'.format(SoD.MODEL_ID))
    def patch_productive(_request):
        return patch_base(_request)

    @perm_required('{}.08'.format(SoD.MODEL_ID))
    def patch_blocked(_request):
        return patch_base(_request)

    @perm_required('{}.09'.format(SoD.MODEL_ID))
    def patch_archived(_request):
        return patch_base(_request)

    @perm_required('{}.10'.format(SoD.MODEL_ID))
    def patch_inactive(_request):
        return patch_base(_request)

    try:
        role = SoD.objects.get(lifecycle_id=lifecycle_id, version=version)
    except SoD.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'PATCH':
        if status == 'circulation':
            return patch_circulation(request)
        if status == 'draft':
            return patch_draft(request)
        if status == 'productive':
            return patch_productive(request)
        if status == 'blocked':
            return patch_blocked(request)
        if status == 'archived':
            return patch_archived(request)
        if status == 'inactive':
            return patch_inactive(request)
        return patch_base(request)


##########
# SODLOG #
##########

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(SoDLog.MODEL_ID))
def sod_log_list(request):
    logs = SoDLog.objects.all()
    serializer = SoDLogReadSerializer(logs, many=True)
    return Response(serializer.data)
