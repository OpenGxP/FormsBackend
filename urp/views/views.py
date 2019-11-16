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
from rest_framework import serializers

# custom imports
from urp.models import Roles, Permissions,  AccessLog, PermissionsLog, RolesLog, Vault
from urp.serializers import StatusReadWriteSerializer, PermissionsReadWriteSerializer, \
    AccessLogReadWriteSerializer, CentralLogReadWriteSerializer, StatusLogReadSerializer, \
    PermissionsLogReadSerializer, AUDIT_TRAIL_SERIALIZERS, UserProfile
from urp.decorators import perm_required, auth_required
from basics.models import Status, StatusLog, CentralLog
from basics.custom import get_model_by_string, unique_items
from urp.vault import create_update_vault
from urp.views.base import auto_logout, GET

# django imports
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate
from django.conf import settings
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.middleware.csrf import get_token
from django.contrib.auth.hashers import make_password


####################
# USER_PERMISSIONS #
####################

@api_view(['GET'])
@auth_required()
@auto_logout()
def user_permissions_view(request):
    data = Roles.objects.permissions(request.user.roles.split(','))
    return Response(data=data, status=http_status.HTTP_200_OK)


#########################
# USER_CHANGE_QUESTIONS #
#########################

@api_view(['PATCH'])
@auth_required()
@auto_logout()
@csrf_protect
def user_change_questions_view(request):
    if not hasattr(request, 'data'):
        raise serializers.ValidationError('Data is required.')

    error_dict = dict()
    field_error = ['This filed is required.']

    # password is always required if security questions are changed
    if 'password' not in request.data:
        error_dict['password'] = field_error

    # all questions / answers must be provided
    question_answer_fields = Vault.question_answers_fields()
    for question, answer in question_answer_fields.items():
        if question not in request.data:
            error_dict[question] = field_error
        if answer not in request.data:
            error_dict[answer] = field_error

    if error_dict:
        raise serializers.ValidationError(error_dict)

    # questions and answers must be unique
    items = list()
    for question, answer in question_answer_fields.items():
        items.append(request.data[question])
        items.append(request.data[answer])

    if not unique_items(items):
        raise serializers.ValidationError('Questions and answers must be unique.')

    try:
        vault = Vault.objects.get(username=request.user.username)
    except Vault.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    data = dict()
    for question, answer in question_answer_fields.items():
        data[question] = request.data[question]
        # save answers like passwords
        data[answer] = make_password(request.data[answer])

    # check if provided password is correct
    now = timezone.now()
    authenticate(request=request, username=request.user.username, password=request.data['password'], now=now,
                 self_question_change=True)

    create_update_vault(data=data, instance=vault, action=settings.DEFAULT_LOG_QUESTIONS, user=request.user.username,
                        signature=False, now=now)

    return Response(status=http_status.HTTP_200_OK)


########
# CSRF #
########

@api_view(['GET'])
@auth_required(initial_password_check=False)
def get_csrf_token(request):
    token = {settings.CSRF_COOKIE_NAME: get_token(request)}
    return Response(data=token, status=http_status.HTTP_200_OK)


##########
# STATUS #
##########

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(Status.MODEL_ID))
def status_list(request):
    get = GET(model=Status, request=request, serializer=StatusReadWriteSerializer)
    return get.standard


#############
# STATUSLOG #
#############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(StatusLog.MODEL_ID))
def status_log_list(request):
    get = GET(model=StatusLog, request=request, serializer=StatusLogReadSerializer)
    return get.standard


###############
# PERMISSIONS #
###############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(Roles.MODEL_ID))
def permissions_list(request):
    get = GET(model=Permissions, request=request, serializer=PermissionsReadWriteSerializer)
    return get.standard


##################
# PERMISSIONSLOG #
##################

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(RolesLog.MODEL_ID))
def permissions_log_list(request):
    get = GET(model=PermissionsLog, request=request, serializer=PermissionsLogReadSerializer)
    return get.standard


##############
# CENTRALLOG #
##############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(CentralLog.MODEL_ID))
def central_log_list(request):
    get = GET(model=CentralLog, request=request, serializer=CentralLogReadWriteSerializer)
    return get.standard


#############
# ACCESSLOG #
#############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(AccessLog.MODEL_ID))
def access_log_list(request):
    get = GET(model=AccessLog, request=request, serializer=AccessLogReadWriteSerializer)
    return get.standard


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


################
# USER_PROFILE #
################

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@ensure_csrf_cookie
def user_profile_list(request):
    try:
        user = Vault.objects.filter(username=request.user.username).get()
    except Vault.DoesNotExist:
        raise serializers.ValidationError('Profile for ldap managed users does not exist.')
    serializer = UserProfile(user)
    return Response(serializer.data)
