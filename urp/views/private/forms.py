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

# app imports
from urp.views.views import auto_logout, GET
from urp.models.forms.forms import Forms
from urp.serializers.forms import FormsReadWriteSerializer, FormsNewVersionStatusSerializer, \
    FormsLogReadSerializer, FormsDeleteSerializer, FormsSectionsLogReadSerializer, FormsTextFieldsLogReadSerializer, \
    FormsBoolFieldsLogReadSerializer
from urp.decorators import auth_required, auth_perm_required
from urp.views.base import StatusView
from urp.models.forms.sub.sections import FormsSectionsLog
from urp.models.forms.sub.text_fields import FormsTextFieldsLog
from urp.models.forms.sub.bool_fields import FormsBoolFieldsLog


view = StatusView(model=Forms, ser_rw=FormsReadWriteSerializer, ser_del=FormsDeleteSerializer,
                  ser_log=FormsLogReadSerializer, ser_st=FormsNewVersionStatusSerializer)


@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def forms_list(request):
    return view.list(request)


@api_view(['GET', 'PATCH', 'POST', 'DELETE'])
@auth_required()
@auto_logout()
def forms_detail(request, lifecycle_id, version):
    return view.detail(request, lifecycle_id, version)


@api_view(['PATCH'])
@auth_required()
@auto_logout()
def forms_status(request, lifecycle_id, version, status):
    return view.status(request, lifecycle_id, version, status)


@api_view(['GET'])
@auth_required()
@auto_logout()
def forms_log_list(request):
    return view.list_log(request)


# sections log
@api_view(['GET'])
@auth_perm_required(permission='{}.01'.format(Forms.MODEL_ID))
@auto_logout()
def forms_sections_log_list(request):
    get = GET(model=FormsSectionsLog, request=request, serializer=FormsSectionsLogReadSerializer)
    return get.standard


# tex fields log
@api_view(['GET'])
@auth_perm_required(permission='{}.01'.format(Forms.MODEL_ID))
@auto_logout()
def forms_text_fields_log_list(request):
    get = GET(model=FormsTextFieldsLog, request=request, serializer=FormsTextFieldsLogReadSerializer)
    return get.standard


# bool fields log
@api_view(['GET'])
@auth_perm_required(permission='{}.01'.format(Forms.MODEL_ID))
@auto_logout()
def forms_bool_fields_log_list(request):
    get = GET(model=FormsBoolFieldsLog, request=request, serializer=FormsBoolFieldsLogReadSerializer)
    return get.standard
