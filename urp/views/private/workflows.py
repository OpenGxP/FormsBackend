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
from rest_framework import status as http_status
from rest_framework.decorators import api_view

# app imports
from urp.views.views import auto_logout
from urp.models.workflows import Workflows, WorkflowsLog
from urp.serializers import WorkflowsReadWriteSerializer, WorkflowsNewVersionStatusSerializer, \
    WorkflowsLogReadSerializer, WorkflowsDeleteSerializer
from urp.decorators import perm_required, auth_required
from basics.models import Status
from urp.models.spaces import Spaces

# django imports
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.db.models import Q


# GET list
@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def workflows_list(request):
    @perm_required('{}.02'.format(Workflows.MODEL_ID))
    @csrf_protect
    def post(_request):
        # add version for new objects because of combined unique constraint
        _request.data['version'] = 1
        _serializer = WorkflowsReadWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                                'function': 'new',
                                                                                'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(Workflows.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        # get tags as , separated string
        tags_str = Spaces.objects.get_tags_by_username(username=_request.user.username)
        # make a list to pass in queryset
        tags_list = []
        if tags_str:
            tags_list = tags_str[0].split(',')
        workflows = Workflows.objects.filter(Q(tag__in=tags_list) | Q(tag='')).all()
        serializer = WorkflowsReadWriteSerializer(workflows, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


# GET detail
@api_view(['GET', 'PATCH', 'POST', 'DELETE'])
@auth_required()
@auto_logout()
def workflows_detail(request, lifecycle_id, version):
    @perm_required('{}.03'.format(Workflows.MODEL_ID))
    @csrf_protect
    def patch(_request):
        _serializer = WorkflowsReadWriteSerializer(_workflow, data=_request.data,
                                                   context={'method': 'PATCH',
                                                            'function': '',
                                                            'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @csrf_protect
    def post_base(_request):
        _serializer = WorkflowsNewVersionStatusSerializer(_workflow, data=_request.data,
                                                          context={'method': 'POST',
                                                                   'function': 'new_version',
                                                                   'user': request.user.username})
        if _serializer.is_valid():
            _serializer.create(validated_data=_serializer.validated_data)
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.11'.format(Workflows.MODEL_ID))
    def post(_request):
        return post_base(_request)

    @perm_required('{}.12'.format(Workflows.MODEL_ID))
    def post_archived(_request):
        return post_base(_request)

    @perm_required('{}.04'.format(Workflows.MODEL_ID))
    @csrf_protect
    def delete(_request):
        _serializer = WorkflowsDeleteSerializer(_workflow, data={}, context={'method': 'DELETE',
                                                                             'function': '',
                                                                             'user': request.user.username})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(Workflows.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        serializer = WorkflowsReadWriteSerializer(_workflow)
        return Response(serializer.data)

    try:
        _workflow = Workflows.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Workflows.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)

    elif request.method == 'POST':
        if _workflow.status.id == Status.objects.archived:
            return post_archived(request)
        else:
            return post(request)

    elif request.method == 'DELETE':
        return delete(request)


@api_view(['PATCH'])
@auth_required()
@auto_logout()
def workflows_status(request, lifecycle_id, version, status):
    @csrf_protect
    def patch_base(_request):
        _serializer = WorkflowsNewVersionStatusSerializer(_workflow, data={},
                                                          context={'method': 'PATCH',
                                                                   'function': 'status_change',
                                                                   'status': status,
                                                                   'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.05'.format(Workflows.MODEL_ID))
    def patch_circulation(_request):
        return patch_base(_request)

    @perm_required('{}.06'.format(Workflows.MODEL_ID))
    def patch_draft(_request):
        return patch_base(_request)

    @perm_required('{}.07'.format(Workflows.MODEL_ID))
    def patch_productive(_request):
        return patch_base(_request)

    @perm_required('{}.08'.format(Workflows.MODEL_ID))
    def patch_blocked(_request):
        return patch_base(_request)

    @perm_required('{}.09'.format(Workflows.MODEL_ID))
    def patch_archived(_request):
        return patch_base(_request)

    @perm_required('{}.10'.format(Workflows.MODEL_ID))
    def patch_inactive(_request):
        return patch_base(_request)

    try:
        _workflow = Workflows.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Workflows.DoesNotExist:
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


# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(WorkflowsLog.MODEL_ID))
def workflows_log_list(request):
    # get tags as , separated string
    tags_str = Spaces.objects.get_tags_by_username(username=request.user.username)
    # make a list to pass in queryset
    tags_list = []
    if tags_str:
        tags_list = tags_str[0].split(',')
    logs = WorkflowsLog.objects.filter(Q(tag__in=tags_list) | Q(tag='')).all()
    serializer = WorkflowsLogReadSerializer(logs, many=True)
    return Response(serializer.data)
