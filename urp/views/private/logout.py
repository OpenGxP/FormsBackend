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
from basics.models import Settings
from urp.decorators import auth_auth_required, auth_required
from urp.backends.users import write_access_log
from urp.views.base import refresh_time

# django imports
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import logout


@api_view(['GET'])
@auth_auth_required()
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


@api_view(['PATCH'])
@auth_required(initial_password_check=False)
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
