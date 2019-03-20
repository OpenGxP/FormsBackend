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
from rest_framework.response import Response
from rest_framework import status as http_status
from rest_framework.decorators import api_view
from rest_framework.reverse import reverse

# custom imports
from .models import Status, Roles, Permissions, Users, AccessLog, PermissionsLog, RolesLog, UsersLog, LDAP, LDAPLog
from .serializers import StatusReadWriteSerializer, PermissionsReadWriteSerializer, RolesReadSerializer, \
    RolesWriteSerializer, UsersReadSerializer, RolesDeleteStatusSerializer, RolesNewVersionSerializer, \
    UsersWriteSerializer, UsersNewVersionSerializer, UsersDeleteStatusSerializer, \
    AccessLogReadWriteSerializer, CentralLogReadWriteSerializer, StatusLogReadSerializer, \
    PermissionsLogReadSerializer, RolesLogReadSerializer, UsersLogReadSerializer, AUDIT_TRAIL_SERIALIZERS, \
    LDAPLogReadSerializer, LDAPReadWriteSerializer, LDAPDeleteSerializer
from .decorators import perm_required, auth_required
from basics.models import StatusLog, CentralLog
from basics.custom import get_model_by_string
from .backends import write_access_log

# django imports
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseRedirect
from django.utils import timezone
from django.conf import settings
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie, csrf_exempt


########
# ROOT #
########

@api_view(['GET'])
def api_root(request):
    return Response({
        'status': reverse('status-list', request=request),
        'status_logs': reverse('status-log-list', request=request),
        'permissions': reverse('permissions-list', request=request),
        'permissions_logs': reverse('permissions-log-list', request=request),
        'central_log': reverse('central-log-list', request=request),
        'access_log': reverse('access-log-list', request=request),
        'roles': reverse('roles-list', request=request),
        'roles_logs': reverse('roles-log-list', request=request),
        'ldap': reverse('ldap-list', request=request),
        'ldap_logs': reverse('ldap-log-list', request=request),
        'users': reverse('users-list', request=request),
        'users_logs': reverse('users-log-list', request=request)
    })


#########
# LOGIN #
#########

@api_view(['POST'])
@csrf_exempt
def login_view(request):
    if Users.USERNAME_FIELD in request.data and 'password' in request.data:
        # authenticate user
        user = authenticate(request=request, username=request.data['username'], password=request.data['password'])
    else:
        raise ValidationError('Fields "{}" and "password are required.'.format(Users.USERNAME_FIELD))
    if user:
        login(request, user)
        return Response(status=http_status.HTTP_200_OK)
    else:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@auth_required()
def logout_view(request):
    data = {
        'user': request.user.username,
        'timestamp': timezone.now(),
        'mode': 'manual',
        'method': settings.DEFAULT_SYSTEM_DEVALUE,
        'action': settings.DEFAULT_LOG_LOGIN,
        'attempt': settings.DEFAULT_LOG_ATTEMPT,
        'active': settings.DEFAULT_SYSTEM_DEVALUE
    }
    logout(request)
    if request.user.is_anonymous:
        write_access_log(data)
    return HttpResponseRedirect('/')


##########
# STATUS #
##########

# GET list
@api_view(['GET'])
@auth_required()
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
@perm_required('08.01')
def permissions_log_list(request):
    """
    List all permissions log records.
    """
    logs = PermissionsLog.objects.all()
    serializer = PermissionsLogReadSerializer(logs, many=True)
    return Response(serializer.data)


###########
# LDAPLOG #
###########

# GET list
@api_view(['GET'])
@auth_required()
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
def ldap_list(request):
    @perm_required('{}.02'.format(LDAPLog.MODEL_ID))
    @csrf_protect
    def post(_request):
        _serializer = LDAPReadWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                           'function': 'new',
                                                                           'user': request.user.username})

        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(LDAPLog.MODEL_ID))
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
def ldap_detail(request, host):
    @perm_required('{}.03'.format(LDAPLog.MODEL_ID))
    @csrf_protect
    def patch(_request):
        _serializer = LDAPReadWriteSerializer(query, data=_request.data, context={'method': 'PATCH',
                                                                                  'function': '',
                                                                                  'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.04'.format(LDAPLog.MODEL_ID))
    @csrf_protect
    def delete(_request):
        _serializer = LDAPDeleteSerializer(query, data={}, context={'method': 'DELETE',
                                                                    'function': '',
                                                                    'user': request.user.username})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(LDAPLog.MODEL_ID))
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


#########
# ROLES #
#########

# GET list
@api_view(['GET', 'POST'])
@auth_required()
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
@perm_required('10.01')
def users_log_list(request):
    """
    List all users log records.
    """
    logs = UsersLog.objects.all()
    serializer = UsersLogReadSerializer(logs, many=True)
    return Response(serializer.data)
