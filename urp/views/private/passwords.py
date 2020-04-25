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

# rest imports
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework import status as http_status
from rest_framework.decorators import api_view

# custom imports
from urp.serializers.passwords import UsersPassword
from urp.decorators import auth_required, auth_perm_required
from urp.models.vault import Vault
from urp.models.users import Users
from urp.views.base import auto_logout, BaseView
from basics.custom import render_email_from_template
from urp.backends.Email import send_email
from urp.vault import validate_password_input, create_update_vault
from urp.custom import validate_signature

# django imports
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect


view = BaseView(model=Vault, ser_rw=UsersPassword)


@api_view(['GET'])
@auth_perm_required(permission='{}.01'.format(Vault.MODEL_ID))
@auto_logout()
@ensure_csrf_cookie
def users_password_list(request):
    return view.list(request)


###################
# PASSWORD_CHANGE #
###################

@api_view(['PATCH'])
@auth_perm_required(permission='{}.13'.format(Vault.MODEL_ID))
@auto_logout()
@csrf_protect
def change_password_view(request, username):
    if not hasattr(request, 'data'):
        raise serializers.ValidationError('Fields "password_new" and "password_new_verification" are required.')
    try:
        vault = Vault.objects.get(username=username)
    except Vault.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    validate_password_input(request.data, instance=vault)

    now = getattr(request, settings.ATTR_NOW, timezone.now())
    # FO-255: changed permission to edit
    signature = validate_signature(dialog='passwords', data=request.data, perm='edit',
                                   logged_in_user=request.user.username, request=request)

    create_update_vault(data=request.data, instance=vault, action=settings.DEFAULT_LOG_PASSWORD,
                        user=request.user.username, signature=signature, now=now)

    # inform user about successful password change
    user = Users.objects.get_valid_by_key(vault.username)
    email_data = {'fullname': user.get_full_name()}
    html_message = render_email_from_template(template_file_name='email_password_changed.html', data=email_data)
    send_email(subject='OpenGxP Password Changed', html_message=html_message, email=user.email)

    return Response(status=http_status.HTTP_200_OK)


########################
# USER_CHANGE_PASSWORD #
########################

@api_view(['PATCH'])
@auth_required(initial_password_check=False)
@auto_logout()
@csrf_protect
def user_change_password_view(request):
    if not hasattr(request, 'data'):
        raise serializers.ValidationError('Fields "password", "password_new" and "password_new_verification" '
                                          'are required.')
    if 'password' not in request.data:
        raise serializers.ValidationError({'password': ['This filed is required.']})

    try:
        vault = Vault.objects.get(username=request.user.username)
    except Vault.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    # check if provided password is correct
    now = getattr(request, settings.ATTR_NOW, timezone.now())
    authenticate(request=request, username=request.user.username, password=request.data['password'],
                 self_password_change=True)

    validate_password_input(request.data, instance=vault)

    create_update_vault(data=request.data, instance=vault, action=settings.DEFAULT_LOG_PASSWORD,
                        user=request.user.username, self_pw=True, signature=False, now=now)

    # inform user about successful password change
    user = Users.objects.get_valid_by_key(vault.username)
    email_data = {'fullname': user.get_full_name()}
    html_message = render_email_from_template(template_file_name='email_password_changed.html', data=email_data)
    send_email(subject='OpenGxP Password Changed', html_message=html_message, email=user.email)

    return Response(status=http_status.HTTP_200_OK)
