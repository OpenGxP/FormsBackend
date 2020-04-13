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
from urp.models import Roles, Permissions, PermissionsLog, RolesLog, Vault
from urp.serializers import StatusReadWriteSerializer, PermissionsReadWriteSerializer, StatusLogReadSerializer, \
    PermissionsLogReadSerializer, UserProfile
from urp.decorators import auth_required, auth_perm_required
from basics.models import Status, StatusLog
from basics.custom import unique_items
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
    data = Roles.objects.permissions(getattr(request.user, 'roles', '').split(','))
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
    now = getattr(request, settings.ATTR_NOW, timezone.now())
    authenticate(request=request, username=request.user.username, password=request.data['password'],
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
@auth_perm_required(permission='{}.01'.format(Status.MODEL_ID))
@auto_logout()
def status_list(request):
    get = GET(model=Status, request=request, serializer=StatusReadWriteSerializer)
    return get.standard


#############
# STATUSLOG #
#############

# GET list
@api_view(['GET'])
@auth_perm_required(permission='{}.01'.format(StatusLog.MODEL_ID))
@auto_logout()
def status_log_list(request):
    get = GET(model=StatusLog, request=request, serializer=StatusLogReadSerializer)
    return get.standard


###############
# PERMISSIONS #
###############

# GET list
@api_view(['GET'])
@auth_perm_required(permission='{}.01'.format(Roles.MODEL_ID))
@auto_logout()
def permissions_list(request):
    get = GET(model=Permissions, request=request, serializer=PermissionsReadWriteSerializer)
    return get.standard


##################
# PERMISSIONSLOG #
##################

# GET list
@api_view(['GET'])
@auth_perm_required(permission='{}.01'.format(RolesLog.MODEL_ID))
@auto_logout()
def permissions_log_list(request):
    get = GET(model=PermissionsLog, request=request, serializer=PermissionsLogReadSerializer)
    return get.standard


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
