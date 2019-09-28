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

# python imports
from collections import OrderedDict

# rest imports
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.response import Response
from rest_framework.utils.urls import replace_query_param, remove_query_param

# django imports
from django.conf import settings


class MyPagination(LimitOffsetPagination):
    max_limit = settings.DEFAULT_PAGINATION_MAX
    default_limit = settings.PROFILE_DEFAULT_PAGINATION_LIMIT

    def get_current_link(self, rel=None):
        url = self.request.build_absolute_uri()
        if rel:
            url = self.request.get_full_path()[1:]
        url = replace_query_param(url, self.limit_query_param, self.limit)
        return replace_query_param(url, self.offset_query_param, self.offset)

    def get_next_link(self, rel=None):
        if self.offset + self.limit >= self.count:
            return None

        url = self.request.build_absolute_uri()
        if rel:
            url = self.request.get_full_path()[1:]
        url = replace_query_param(url, self.limit_query_param, self.limit)

        offset = self.offset + self.limit
        return replace_query_param(url, self.offset_query_param, offset)

    def get_previous_link(self, rel=None):
        if self.offset <= 0:
            return None

        url = self.request.build_absolute_uri()
        if rel:
            url = self.request.get_full_path()[1:]
        url = replace_query_param(url, self.limit_query_param, self.limit)

        if self.offset - self.limit <= 0:
            return remove_query_param(url, self.offset_query_param)

        offset = self.offset - self.limit
        return replace_query_param(url, self.offset_query_param, offset)

    def get_paginated_response(self, data):
        end = self.offset + self.limit
        if end > self.count:
            end = self.count
        return Response(OrderedDict([
            ('count', self.count),
            ('limit', self.limit),
            ('offset', self.offset + 1),
            ('end', end),
            ('next_abs', self.get_next_link()),
            ('next_rel', self.get_next_link(rel=True)),
            ('current_abs', self.get_current_link()),
            ('current_rel', self.get_current_link(rel=True)),
            ('previous_abs', self.get_previous_link()),
            ('previous_rel', self.get_previous_link(rel=True)),
            ('results', data)
        ]))
