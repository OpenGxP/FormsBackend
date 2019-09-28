"""
opengxp.org
Copyright (C) 2019 Henrik Baran

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

# python imports
from functools import wraps

# rest imports
from rest_framework.response import Response
from rest_framework import status as http_status

# app imports
from basics.models import Settings, Status
from urp.backends.User import write_access_log
from urp.pagination import MyPagination
from urp.models.profile import Profile
from urp.models.spaces import Spaces
from urp.decorators import perm_required

# django imports
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import logout
from django.db.models import Q
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie


def refresh_time(request, active=True):
    now = timezone.now()
    if now - request.session['last_touch'] > timezone.timedelta(minutes=Settings.objects.core_auto_logout):
        data = {
            'user': request.user.username,
            'timestamp': now,
            'mode': 'automatic',
            'method': Settings.objects.core_devalue,
            'action': settings.DEFAULT_LOG_LOGOUT,
            'attempt': Settings.objects.core_devalue,
            'active': Settings.objects.core_devalue
        }
        logout(request)
        if request.user.is_anonymous:
            write_access_log(data)
    else:
        # only refresh if user was active (default for request)
        if active:
            request.session['last_touch'] = now
        return True


def auto_logout():
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # use method
            if refresh_time(request=request):
                return view_func(request, *args, **kwargs)
            else:
                return Response(status=http_status.HTTP_401_UNAUTHORIZED)
        return wrapper
    return decorator


class GET(object):
    tags = False

    def __init__(self, model, request, serializer, _filter=None):
        # paginator
        self.paginator = MyPagination()
        limit = Profile.objects.pagination_limit(username=request.user.username)
        self.paginator.limit = limit
        self.paginator.default_limit = limit

        # attributes
        self.model = model
        self.request = request
        self.serializer = serializer

        # filter
        if _filter:
            self.filter_set_strict = _filter
        else:
            self.filter_set_strict = {}

        # data
        self.model_fields = [i.name for i in self.model._meta.get_fields()]
        self.sort_field = ''
        self.filter_set_query = {}
        self.or_filter = False

        # parse query
        self.parse_query_param()

    @property
    def filter_base(self):
        return self.model.objects.filter(**self.filter_set_strict)

    def parse_query_param(self):
        filter_set = {}
        for param in self.request.query_params:
            # ignore pagination parameter
            if param == self.paginator.offset_query_param or param == self.paginator.limit_query_param:
                continue

            if param == 'order_by':
                kv = self.request.query_params[param].split('.')
                try:
                    field = kv[0]
                    direction = kv[1]
                except IndexError:
                    pass
                else:
                    if field in self.model_fields:
                        if direction == 'desc' and not self.sort_field:
                            self.sort_field = '-{}'.format(field)
                        if direction == 'asc' and not self.sort_field:
                            self.sort_field = field
                        continue

            if param in self.model_fields:
                filter_set['{}__contains'.format(param)] = self.request.query_params[param]

        self.filter_set_query = filter_set

    @property
    def model_object_base(self):
        if self.sort_field:
            return self.filter_base.filter(**self.filter_set_query).order_by(self.sort_field)
        return self.filter_base.filter(**self.filter_set_query)

    @property
    def serialized(self):
        return self.serializer(self.paginated, many=True, context={'user': self.request.user.username})

    @property
    def paginated(self):
        return self.paginator.paginate_queryset(self.queryset, self.request)

    @property
    def tags_list(self):
        tags_str = Spaces.objects.get_tags_by_username(username=self.request.user.username)
        tags_list = []
        if tags_str:
            tags_list = tags_str[0].split(',')
        return tags_list

    @property
    def queryset(self):
        if not self.tags:
            return self.model_object_base.all()
        return self.model_object_base.filter(Q(tag__in=self.tags_list) | Q(tag='')).all()

    @property
    def paginated_response(self):
        response = self.paginator.get_paginated_response(self.serialized.data)
        setattr(response, 'data', dict(response.data))
        if len(response.data['results']) == 1:
            response.data['results'] = [dict(response.data['results'][0])]
        else:
            if len(response.data['results']) > 1:
                tmp_list = []
                for item in response.data['results']:
                    tmp_list.append(dict(item))
                response.data['results'] = tmp_list
        return response

    @property
    def standard(self):
        return self.paginated_response


def post(request, ser_rw):
    request.data['version'] = 1
    serializer = ser_rw(data=request.data, context={'method': 'POST',
                                                    'function': 'new',
                                                    'user': request.user.username})
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=http_status.HTTP_201_CREATED)
    return Response(serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)


def update(request, ser_rw, query):
    serializer = ser_rw(query, data=request.data, context={'method': 'PATCH', 'function': '',
                                                           'user': request.user.username})
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)


def delete(request, ser_del, query):
    serializer = ser_del(query, data={}, context={'method': 'DELETE', 'function': '',
                                                  'user': request.user.username})
    if serializer.is_valid():
        serializer.delete()
        return Response(status=http_status.HTTP_204_NO_CONTENT)
    return Response(serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)


class BaseView(object):
    def __init__(self, model, ser_rw, ser_log=None):
        self.model = model
        self.log_model = model.objects.LOG_TABLE

        # serializers
        self.ser_rw = ser_rw
        self.ser_log = ser_log

    def list(self, request, tags=None, ext_filter=None):
        # permissions
        perm_read = '{}.01'.format(self.model.MODEL_ID)
        perm_add = '{}.02'.format(self.model.MODEL_ID)

        # serializer
        ser_rw = self.ser_rw

        @perm_required(perm_add)
        @csrf_protect
        def _post(_request):
            return post(request, ser_rw)

        @perm_required(perm_read)
        @ensure_csrf_cookie
        def get(_request):
            _get = GET(model=self.model, request=request, serializer=ser_rw, _filter=ext_filter)
            if tags:
                _get.tags = True
            return _get.standard

        if request.method == 'GET':
            return get(request)
        if request.method == 'POST':
            return _post(request)

    def list_log(self, request, tags=None, ext_filter=None):
        perm_read = '{}.01'.format(self.log_model.MODEL_ID)

        @perm_required(perm_read)
        def main(_request):
            get = GET(self.log_model, request=request, serializer=self.ser_log, _filter=ext_filter)
            if tags:
                get.tags = True
            return get.standard

        return main(request)


class UpdateView(BaseView):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def detail(self, request, unique, ext_filter=None):
        # permissions
        perm_read = '{}.01'.format(self.model.MODEL_ID)
        perm_patch = '{}.03'.format(self.model.MODEL_ID)

        # serializer
        ser_rw = self.ser_rw

        @perm_required(perm_patch)
        @csrf_protect
        def patch(_request):
            return update(request, ser_rw, query)

        @perm_required(perm_read)
        @ensure_csrf_cookie
        def get(_request):
            _get = GET(model=self.model, request=request, serializer=ser_rw, _filter=_filter)
            return _get.standard

        try:
            if ext_filter:
                unique_filter = {self.model.UNIQUE: unique}
                _filter = {**unique_filter, **ext_filter}
            else:
                _filter = {self.model.UNIQUE: unique}
            query = self.model.objects.get(**_filter)
        except self.model.DoesNotExist:
            return Response(status=http_status.HTTP_404_NOT_FOUND)
        except ValidationError:
            return Response(status=http_status.HTTP_400_BAD_REQUEST)

        if request.method == 'GET':
            return get(request)
        elif request.method == 'PATCH':
            return patch(request)


class StandardView(BaseView):
    def __init__(self, ser_del, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # serializers
        self.ser_del = ser_del

    def detail(self, request, unique):
        # permissions
        perm_read = '{}.01'.format(self.model.MODEL_ID)
        perm_patch = '{}.03'.format(self.model.MODEL_ID)
        perm_del = '{}.04'.format(self.model.MODEL_ID)

        # serializer
        ser_rw = self.ser_rw
        ser_del = self.ser_del

        @perm_required(perm_patch)
        @csrf_protect
        def patch(_request):
            return update(request, ser_rw, query)

        @perm_required(perm_del)
        @csrf_protect
        def _delete(_request):
            return delete(request, ser_del, query)

        @perm_required(perm_read)
        @ensure_csrf_cookie
        def get(_request):
            _get = GET(model=self.model, request=request, serializer=ser_rw, _filter=_filter)
            return _get.standard

        try:
            _filter = {self.model.UNIQUE: unique}
            query = self.model.objects.get(**_filter)
        except self.model.DoesNotExist:
            return Response(status=http_status.HTTP_404_NOT_FOUND)
        except ValidationError:
            return Response(status=http_status.HTTP_400_BAD_REQUEST)

        if request.method == 'GET':
            return get(request)
        elif request.method == 'PATCH':
            return patch(request)
        elif request.method == 'DELETE':
            return _delete(request)


class StatusView(BaseView):
    def __init__(self, ser_st, ser_del, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # serializers
        self.ser_del = ser_del
        self.ser_st = ser_st

    def list(self, request, tags=True, ext_filter=None):
        return super().list(request, tags, ext_filter)

    def detail(self, request, lifecycle_id, version, tags=True):
        # permissions
        perm_read = '{}.01'.format(self.model.MODEL_ID)
        perm_patch = '{}.03'.format(self.model.MODEL_ID)
        perm_del = '{}.04'.format(self.model.MODEL_ID)
        perm_nv = '{}.11'.format(self.model.MODEL_ID)
        perm_nva = '{}.12'.format(self.model.MODEL_ID)

        # serializer
        ser_rw = self.ser_rw
        ser_st = self.ser_st
        ser_del = self.ser_del

        @perm_required(perm_patch)
        @csrf_protect
        def patch(_request):
            return update(request, ser_rw, query)

        @csrf_protect
        def new_version_base(_request):
            serializer = ser_st(query, data=request.data, context={'method': 'POST', 'function': 'new_version',
                                                                   'user': request.user.username})
            if serializer.is_valid():
                serializer.create(validated_data=serializer.validated_data)
                return Response(serializer.data, status=http_status.HTTP_201_CREATED)
            return Response(serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

        @perm_required(perm_nv)
        def new_version(_request):
            return new_version_base(_request)

        @perm_required(perm_nva)
        def new_version_archived(_request):
            return new_version_base(_request)

        @perm_required(perm_del)
        @csrf_protect
        def _delete(_request):
            return delete(request, ser_del, query)

        @perm_required(perm_read)
        @ensure_csrf_cookie
        def get(_request):
            _get = GET(model=self.model, request=request, serializer=ser_rw, _filter=_filter)
            if tags:
                _get.tags = True
            return _get.standard

        try:
            _filter = {'lifecycle_id': lifecycle_id,
                       'version': version}
            query = self.model.objects.get(**_filter)
        except self.model.DoesNotExist:
            return Response(status=http_status.HTTP_404_NOT_FOUND)
        except ValidationError:
            return Response(status=http_status.HTTP_400_BAD_REQUEST)

        if request.method == 'GET':
            return get(request)
        elif request.method == 'PATCH':
            return patch(request)
        elif request.method == 'POST':
            if query.status.id == Status.objects.archived:
                return new_version_archived(request)
            else:
                return new_version(request)
        elif request.method == 'DELETE':
            return _delete(request)

    def status(self, request, lifecycle_id, version, status):
        # permissions
        perm_circ = '{}.05'.format(self.model.MODEL_ID)
        perm_draft = '{}.06'.format(self.model.MODEL_ID)
        perm_prod = '{}.07'.format(self.model.MODEL_ID)
        perm_block = '{}.08'.format(self.model.MODEL_ID)
        perm_arch = '{}.09'.format(self.model.MODEL_ID)
        perm_inac = '{}.10'.format(self.model.MODEL_ID)

        # serializer
        ser_st = self.ser_st

        @csrf_protect
        def patch_base(_request):
            serializer = ser_st(query, data={}, context={'method': 'PATCH', 'function': 'status_change',
                                                         'status': status, 'user': request.user.username})
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

        @perm_required(perm_circ)
        def patch_circulation(_request):
            return patch_base(_request)

        @perm_required(perm_draft)
        def patch_draft(_request):
            return patch_base(_request)

        @perm_required(perm_prod)
        def patch_productive(_request):
            return patch_base(_request)

        @perm_required(perm_block)
        def patch_blocked(_request):
            return patch_base(_request)

        @perm_required(perm_arch)
        def patch_archived(_request):
            return patch_base(_request)

        @perm_required(perm_inac)
        def patch_inactive(_request):
            return patch_base(_request)

        try:
            query = self.model.objects.get(lifecycle_id=lifecycle_id, version=version)
        except self.model.DoesNotExist:
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

    def list_log(self, request, tags=True, ext_filter=None):
        return super().list_log(request, tags, ext_filter)
