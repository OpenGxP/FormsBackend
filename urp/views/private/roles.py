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
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status as http_status

# app imports
from urp.models.ldap import LDAP
from urp.views.views import auto_logout
from urp.models.roles import Roles
from urp.serializers.roles import RolesReadWriteSerializer, RolesLogReadSerializer, RolesDeleteSerializer, \
    RolesNewVersionStatusSerializer
from urp.decorators import auth_perm_required, auth_required, auth_auth_required
from urp.views.base import StatusView
from urp.custom import validate_comment, validate_signature


view = StatusView(model=Roles, ser_rw=RolesReadWriteSerializer, ser_del=RolesDeleteSerializer,
                  ser_log=RolesLogReadSerializer, ser_st=RolesNewVersionStatusSerializer)


@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def roles_list(request):
    return view.list(request, tags=False)


@api_view(['POST'])
@auth_auth_required()
@auto_logout()
def roles_list_validate(request):
    return view.list(request, validate_only=True)


@api_view(['GET', 'PATCH', 'POST', 'DELETE'])
@auth_required()
@auto_logout()
def roles_detail(request, lifecycle_id, version):
    return view.detail(request, lifecycle_id, version, tags=False)


@api_view(['PATCH'])
@auth_auth_required()
@auto_logout()
def roles_detail_validate(request, lifecycle_id, version):
    return view.detail(request, lifecycle_id, version, validate_only=True)


@api_view(['PATCH'])
@auth_required()
@auto_logout()
def roles_status(request, lifecycle_id, version, status):
    return view.status(request, lifecycle_id, version, status)


@api_view(['GET'])
@auth_required()
@auto_logout()
def roles_log_list(request):
    return view.list_log(request, tags=False)


@api_view(['GET'])
@auth_perm_required(permission='{}.13'.format(Roles.MODEL_ID))
@auto_logout()
def roles_ldap(request):
    validate_comment(dialog='roles', data=request.data, perm='ldap')
    signature = validate_signature(logged_in_user=request.user.username, dialog='roles', data=request.data, perm='ldap',
                                   request=request)

    groups = LDAP.objects.search_groups
    for grp in groups:
        data = {'role': grp,
                'version': 1}
        serializer = RolesReadWriteSerializer(data=data, context={'method': 'POST',
                                                                  'function': 'new',
                                                                  'user': request.user.username,
                                                                  'request': request,
                                                                  'signature': signature})
        if serializer.is_valid():
            serializer.save()
    return Response(status=http_status.HTTP_200_OK)
