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

# python imports
from functools import wraps

# rest imports
from rest_framework.response import Response
from rest_framework import status as http_status

# app imports
from basics.models import Settings, Status
from urp.backends.users import write_access_log
from urp.pagination import MyPagination
from urp.models.profile import Profile
from urp.models.spaces import Spaces
from urp.decorators import perm_required
from urp.models.roles import Roles

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
        # no pagination for permissions
        if model.MODEL_ID == '02':
            limit = settings.DEFAULT_PERMISSIONS_PAGINATION_LIMIT
        else:
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
        self.model_fields = [i.name for i in getattr(self.model, '_meta').get_fields()]
        self.sort_field = ''
        self.filter_set_query = {}
        self.or_filter = False

        # parse query
        self.parse_query_param()

    @property
    def filter_base(self):
        return self.model.objects.filter(**self.filter_set_strict)

    @staticmethod
    def replace_local(field):
        # route calculated fields
        if field in ['timestamp_local', 'valid_from_local', 'valid_to_local']:
            return field.replace('_local', '')
        return field

    def parse_query_param(self):
        # global Q
        g_q = Q()

        # default global and/or is AND
        g_and_or = Q.AND

        # catch global and/or
        if 'and_or' in self.request.query_params:
            if self.request.query_params['and_or'] == 'or':
                g_and_or = Q.OR

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
                    # route calculated fields
                    field = self.replace_local(field)
                    if field in self.model_fields:
                        if direction == 'desc' and not self.sort_field:
                            self.sort_field = '-{}'.format(field)
                        if direction == 'asc' and not self.sort_field:
                            self.sort_field = field
                continue

            # route calculated fields
            # FO-265: keep param with _local to find key in query parameters
            param_old = param
            param = self.replace_local(param)
            if param in self.model_fields:
                # split between filter conditions and and/or
                # FO-265: use param_old with _local to find key in query parameters
                major_split = self.request.query_params[param_old].split('_')
                and_or = Q.AND
                if len(major_split) == 2:
                    if major_split[1] == 'or':
                        and_or = Q.OR
                chain = major_split[0].split(',')
                q = Q()
                for i in chain:
                    kv = i.split('.')
                    try:
                        cond = kv[0]
                        value = kv[1]
                    except IndexError:
                        pass
                    else:
                        if not isinstance(cond, str) or not isinstance(value, str):
                            continue
                        if param in ['timestamp', 'valid_from', 'valid_to'] and cond == 'exact':
                            continue
                        if param == 'status':
                            status_value = Status.objects.status_by_text(value)
                            if status_value:
                                q.add(Q(**{'status__exact': status_value}), and_or)
                                continue
                            else:
                                continue
                        filter_options = ['contains', 'exact', 'startswith', 'endswith']
                        if cond in filter_options:
                            q.add(Q(**{'{}__{}'.format(param, cond): value}), and_or)
                        if cond == 'notexact':
                            q.add(~Q(**{'{}__exact'.format(param): value}), and_or)
                        if cond == 'wildcard':
                            wild_q = Q()
                            for x in value.split('*'):
                                if x:
                                    wild_q.add(Q(**{'{}__contains'.format(param): x}), Q.AND)
                            q.add(wild_q, and_or)

                g_q.add(q, g_and_or)
                continue
        self.filter_set_query = g_q

    @property
    def model_object_base(self):
        if self.sort_field:
            return self.filter_base.filter(self.filter_set_query).order_by(self.sort_field)
        return self.filter_base.filter(self.filter_set_query)

    @property
    def serialized(self):
        return self.serializer(self.paginated, many=True, context={'user': self.request.user.username})

    @property
    def paginated(self):
        return self.paginator.paginate_queryset(self.queryset, self.request)

    @property
    def tags_list(self):
        # FO-226: get all tags related to a user via spaces, not only one (first)
        tags_list_raw = list(Spaces.objects.get_tags_by_username(username=self.request.user.username))
        tags_list_clean = []
        if tags_list_raw:
            for item in tags_list_raw:
                # items can be single strings or strings comma separated
                # if comma is in item, it is a comma separated string list that must be handled
                if ',' in item:
                    # split the string to a list
                    x = item.split(',')
                    # iterate over the list and add each item/i to clean list
                    for i in x:
                        tags_list_clean.append(i)
                # if no comma in string, add item directly to clean list
                else:
                    tags_list_clean.append(item)
            # because clean list contains duplicates, they are removed
            tags_list_clean = list(set(tags_list_clean))
        return tags_list_clean

    @property
    def queryset(self):
        if not self.tags:
            return self.model_object_base.all()
        # FO-227: check if user has initial / all role.
        if self.request.user.has_role(Settings.objects.core_initial_role):
            # if user has role, then validate if role is prod/valid
            if Roles.objects.verify_prod_valid(key=Settings.objects.core_initial_role):
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


def post(request, ser_rw, validate_only=False):
    request.data['version'] = 1
    serializer = ser_rw(data=request.data, context={'method': 'POST',
                                                    'function': 'new',
                                                    'user': request.user.username,
                                                    'request': request})
    if serializer.is_valid():
        if not validate_only:
            serializer.save()
            return Response(serializer.data, status=http_status.HTTP_201_CREATED)
        else:
            return Response(status=http_status.HTTP_200_OK)
    return Response(serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)


def update(request, ser_rw, query, validate_only=False):
    serializer = ser_rw(query, data=request.data, context={'method': 'PATCH', 'function': '',
                                                           'user': request.user.username,
                                                           'request': request})
    if serializer.is_valid():
        if not validate_only:
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(status=http_status.HTTP_200_OK)
    return Response(serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)


def delete(request, ser_del, query):
    serializer = ser_del(query, data=request.data, context={'method': 'DELETE', 'function': '',
                                                            'user': request.user.username,
                                                            'request': request})
    if serializer.is_valid():
        serializer.delete()
        return Response(status=http_status.HTTP_204_NO_CONTENT)
    return Response(serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)


class BaseView(object):
    def __init__(self, model, ser_rw, ser_log=None):
        self.model = model
        # FO-235: add global indicator if model has permissions
        self.perms = model.perms
        self.log_model = model.objects.LOG_TABLE

        # serializers
        self.ser_rw = ser_rw
        self.ser_log = ser_log

    def list(self, request, tags=None, ext_filter=None, validate_only=False):
        # permissions
        # FO-235: if model has permissions use them, otherwise pass None to avoid restriction
        if self.perms:
            perm_read = '{}.01'.format(self.model.MODEL_ID)
            perm_add = '{}.02'.format(self.model.MODEL_ID)
        else:
            perm_read = None
            perm_add = None

        if validate_only:
            perm_add = None

        # serializer
        ser_rw = self.ser_rw

        @perm_required(perm_add)
        @csrf_protect
        def _post(_request):
            return post(request, ser_rw, validate_only=validate_only)

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
        # permissions
        # FO-235: if model has permissions use them, otherwise pass None to avoid restriction
        if self.perms:
            perm_read = '{}.01'.format(self.log_model.MODEL_ID)
        else:
            perm_read = None

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

    def detail(self, request, unique, ext_filter=None, validate_only=False):
        # permissions
        # FO-235: if model has permissions use them, otherwise pass None to avoid restriction
        if self.perms:
            perm_read = '{}.01'.format(self.model.MODEL_ID)
            perm_patch = '{}.03'.format(self.model.MODEL_ID)
        else:
            perm_read = None
            perm_patch = None

        if validate_only:
            perm_patch = None

        # serializer
        ser_rw = self.ser_rw

        @perm_required(perm_patch)
        @csrf_protect
        def patch(_request):
            return update(request, ser_rw, query, validate_only=validate_only)

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

    def detail(self, request, unique, validate_only=False):
        # permissions
        # FO-235: if model has permissions use them, otherwise pass None to avoid restriction
        if self.perms:
            perm_read = '{}.01'.format(self.model.MODEL_ID)
            perm_patch = '{}.03'.format(self.model.MODEL_ID)
            perm_del = '{}.04'.format(self.model.MODEL_ID)
        else:
            perm_read = None
            perm_patch = None
            perm_del = None

        if validate_only:
            perm_patch = None

        # serializer
        ser_rw = self.ser_rw
        ser_del = self.ser_del

        @perm_required(perm_patch)
        @csrf_protect
        def patch(_request):
            return update(request, ser_rw, query, validate_only=validate_only)

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

    def list(self, request, tags=True, ext_filter=None, validate_only=False):
        return super().list(request, tags, ext_filter, validate_only)

    def detail(self, request, lifecycle_id, version, tags=True, validate_only=False):
        # permissions
        # FO-235: if model has permissions use them, otherwise pass None to avoid restriction
        if self.perms:
            perm_read = '{}.01'.format(self.model.MODEL_ID)
            perm_patch = '{}.03'.format(self.model.MODEL_ID)
            perm_del = '{}.04'.format(self.model.MODEL_ID)
            perm_nv = '{}.11'.format(self.model.MODEL_ID)
            perm_nva = '{}.12'.format(self.model.MODEL_ID)
        else:
            perm_read = None
            perm_patch = None
            perm_del = None
            perm_nv = None
            perm_nva = None

        if validate_only:
            perm_patch = None

        # serializer
        ser_rw = self.ser_rw
        ser_st = self.ser_st
        ser_del = self.ser_del

        @perm_required(perm_patch)
        @csrf_protect
        def patch(_request):
            return update(request, ser_rw, query, validate_only=validate_only)

        @csrf_protect
        def new_version_base(_request, nv):
            serializer = ser_st(query, data=request.data, context={'method': 'POST', 'function': 'new_version',
                                                                   'user': request.user.username, 'nv': nv,
                                                                   'request': request})
            if serializer.is_valid():
                serializer.create(validated_data=serializer.validated_data)
                return Response(serializer.data, status=http_status.HTTP_201_CREATED)
            return Response(serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

        @perm_required(perm_nv)
        def new_version(_request):
            return new_version_base(_request, nv='regular')

        @perm_required(perm_nva)
        def new_version_archived(_request):
            return new_version_base(_request, nv='archived')

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
        # FO-235: if model has permissions use them, otherwise pass None to avoid restriction
        if self.perms:
            perm_circ = '{}.05'.format(self.model.MODEL_ID)
            perm_draft = '{}.06'.format(self.model.MODEL_ID)
            perm_prod = '{}.07'.format(self.model.MODEL_ID)
            perm_block = '{}.08'.format(self.model.MODEL_ID)
            perm_arch = '{}.09'.format(self.model.MODEL_ID)
            perm_inac = '{}.10'.format(self.model.MODEL_ID)
        else:
            perm_circ = None
            perm_draft = None
            perm_prod = None
            perm_block = None
            perm_arch = None
            perm_inac = None

        # serializer
        ser_st = self.ser_st

        @csrf_protect
        def patch_base(_request):
            serializer = ser_st(query, data=request.data, context={'method': 'PATCH', 'function': 'status_change',
                                                                   'status': status, 'user': request.user.username,
                                                                   'request': request})
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


class RTDView(StatusView):
    def __init__(self, ser_value, model_exec, model_exec_log, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # serializers
        self.ser_value = ser_value
        self.model_exec = model_exec
        self.model_exec_log = model_exec_log

    def detail(self, request, number, lifecycle_id=None, version=None, tags=True):
        # permissions
        # FO-235: if model has permissions use them, otherwise pass None to avoid restriction
        if self.perms:
            perm_read = '{}.01'.format(self.model.MODEL_ID)
            perm_patch = '{}.03'.format(self.model.MODEL_ID)
            perm_del = '{}.04'.format(self.model.MODEL_ID)
        else:
            perm_read = None
            perm_patch = None
            perm_del = None

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
            if tags:
                _get.tags = True
            return _get.standard

        try:
            _filter = {'number': number}
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

    def status(self, request, number, status, lifecycle_id=None, version=None):
        # permissions
        # FO-235: if model has permissions use them, otherwise pass None to avoid restriction
        if self.perms:
            perm_start = '{}.05'.format(self.model.MODEL_ID)
            perm_cancel = '{}.06'.format(self.model.MODEL_ID)
            perm_complete = '{}.07'.format(self.model.MODEL_ID)
        else:
            perm_start = None
            perm_cancel = None
            perm_complete = None

        # serializer
        ser_st = self.ser_st

        @csrf_protect
        def patch_base(_request):
            serializer = ser_st(query, data=request.data, context={'method': 'PATCH', 'function': 'status_change',
                                                                   'status': status, 'user': request.user.username,
                                                                   'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

        @perm_required(perm_start)
        def patch_start(_request):
            return patch_base(_request)

        @perm_required(perm_cancel)
        def patch_cancel(_request):
            return patch_base(_request)

        @perm_required(perm_complete)
        def patch_complete(_request):
            return patch_base(_request)

        try:
            query = self.model.objects.get(number=number)
        except self.model.DoesNotExist:
            return Response(status=http_status.HTTP_404_NOT_FOUND)
        except ValidationError:
            return Response(status=http_status.HTTP_400_BAD_REQUEST)

        if request.method == 'PATCH':
            if status == 'started':
                return patch_start(request)
            if status == 'canceled':
                return patch_cancel(request)
            if status == 'complete':
                return patch_complete(request)
            return patch_base(request)

    def value(self, request, number, section, field):
        # permissions
        # FO-235: if model has permissions use them, otherwise pass None to avoid restriction
        if self.perms:
            perm_patch = '{}.03'.format(self.model.MODEL_ID)
            perm_correct = '{}.08'.format(self.model.MODEL_ID)
        else:
            perm_patch = None
            perm_correct = None

        # serializer
        ser_value = self.ser_value

        @perm_required(perm_patch)
        @csrf_protect
        def patch(_request):
            return update(request, ser_value, query)

        @perm_required(perm_correct)
        @perm_required(perm_patch)
        @csrf_protect
        def patch_correct(_request):
            return update(request, ser_value, query)

        try:
            query = self.model_exec.objects.get(number__exact=number, section__exact=section, field__exact=field)
        except self.model_exec.DoesNotExist:
            return Response(status=http_status.HTTP_404_NOT_FOUND)
        except ValidationError:
            return Response(status=http_status.HTTP_400_BAD_REQUEST)

        if request.method == 'PATCH':
            if getattr(query, 'value'):
                return patch_correct(request)
            else:
                return patch(request)

    def list_log_value(self, request, tags=True, ext_filter=None):
        log_model = self.model_exec.objects.LOG_TABLE
        # permissions
        # FO-235: if model has permissions use them, otherwise pass None to avoid restriction
        if self.perms:
            perm_read = '{}.01'.format(log_model.MODEL_ID)
        else:
            perm_read = None

        @perm_required(perm_read)
        def main(_request):
            get = GET(log_model, request=request, serializer=self.model_exec_log, _filter=ext_filter)
            if tags:
                get.tags = True
            return get.standard

        return main(request)
