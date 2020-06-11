"""
opengxp.org
Copyright (C) 2020 Henrik Baran

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
from urp.views.views import auto_logout
from urp.models.execution.execution import Execution
from urp.serializers.execution import ExecutionReadWriteSerializer, ExecutionStatusSerializer, \
    ExecutionLogReadSerializer, ExecutionDeleteSerializer, ExecutionTextFieldsWriteSerializer, \
    ExecutionBoolFieldsWriteSerializer, ExecutionFieldsLogReadSerializer, ExecutionSectionsSignSerializer
from urp.decorators import auth_required
from urp.views.base import RTDView
from urp.models.execution.view import ExecutionActualValuesLog
from urp.models.execution.sub.bool_fields import ExecutionBoolFields
from urp.models.execution.sub.text_fields import ExecutionTextFields


model_ser_pairs = {ExecutionTextFields: ExecutionTextFieldsWriteSerializer,
                   ExecutionBoolFields: ExecutionBoolFieldsWriteSerializer}


view = RTDView(model=Execution, ser_rw=ExecutionReadWriteSerializer, ser_del=ExecutionDeleteSerializer,
               ser_log=ExecutionLogReadSerializer, ser_st=ExecutionStatusSerializer, model_ser_pairs=model_ser_pairs,
               log_model_view=ExecutionActualValuesLog, log_model_view_ser=ExecutionFieldsLogReadSerializer,
               ser_sections=ExecutionSectionsSignSerializer)


@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def execution_list(request):
    return view.list(request)


@api_view(['GET', 'DELETE'])
@auth_required()
@auto_logout()
def execution_detail(request, number):
    return view.detail(request, number)


@api_view(['PATCH'])
@auth_required()
@auto_logout()
def execution_status(request, number, status):
    return view.status(request, number, status)


@api_view(['PATCH'])
@auth_required()
@auto_logout()
def execution_value(request, number, section, field):
    return view.value(request, number, section, field)


@api_view(['POST'])
@auth_required()
@auto_logout()
def execution_section(request, number, section):
    return view.section(request, number, section)


@api_view(['GET'])
@auth_required()
@auto_logout()
def execution_log_list(request):
    return view.list_log(request)


@api_view(['GET'])
@auth_required()
@auto_logout()
def list_log_value(request):
    return view.list_log_value(request)
