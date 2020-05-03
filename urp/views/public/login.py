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
from rest_framework.response import Response
from rest_framework import serializers
from rest_framework.decorators import api_view
from rest_framework import status as http_status

# app imports
from urp.models import Users
from urp.models.profile import Profile

# django imports
from django.utils import timezone
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login


@api_view(['POST'])
@csrf_exempt
def login_view(request):
    # FO-137: adapted validation properly and raise serializer validation error (including 400 response)
    if not hasattr(request, 'data'):
        raise serializers.ValidationError('Fields "{}" and "password" are required.'.format(Users.USERNAME_FIELD))

    error_dict = {}
    error_text = ['This filed is required.']
    if Users.USERNAME_FIELD not in request.data:
        error_dict[Users.USERNAME_FIELD] = error_text
    else:
        if not request.data[Users.USERNAME_FIELD]:
            error_dict[Users.USERNAME_FIELD] = error_text
    if 'password' not in request.data:
        error_dict['password'] = error_text
    else:
        if not request.data['password']:
            error_dict['password'] = error_text
    if error_dict:
        raise serializers.ValidationError(error_dict)

    # FO-137: adapted validation properly and raise serializer validation error (including 400 response)
    error_text = ['This filed requires data type string.']
    if not isinstance(request.data[Users.USERNAME_FIELD], str):
        error_dict[Users.USERNAME_FIELD] = error_text
    if not isinstance(request.data['password'], str):
        error_dict['password'] = error_text

    if error_dict:
        raise serializers.ValidationError(error_dict)

    user = None

    if not error_dict:
        try:
            user = authenticate(request=request, username=request.data['username'], password=request.data['password'],
                                initial_password_check=False, public=True)
        except serializers.ValidationError as e:
            error_dict['password'] = e.detail
            error_dict[Users.USERNAME_FIELD] = e.detail

    if error_dict:
        raise serializers.ValidationError(error_dict)

    if user:
        login(request, user)
        request.session['last_touch'] = timezone.now()
        # pass authenticated user roles to casl method, split to parse
        data = dict()
        # get initial password fag of user
        data['initial_password'] = user.initial_password
        data['initial_timezone'] = Profile.objects.initial_timezone(user.username)
        data['casl'] = getattr(request, settings.ATTR_CASL, [])
        return Response(data=data, status=http_status.HTTP_200_OK)
    else:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)
