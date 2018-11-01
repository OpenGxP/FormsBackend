"""
opengxp.org
Copyright (C) 2018  Henrik Baran

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
from rest_framework.urlpatterns import format_suffix_patterns

# django imports
from django.conf.urls import url

# app imports
from .views import StatusList, RolesList, PermissionsList, UsersList


urlpatterns = [
    url('status/', StatusList.as_view()),
    url('roles/', RolesList.as_view()),
    url('permissions/', PermissionsList.as_view()),
    url('users/', UsersList.as_view())
]

urlpatterns = format_suffix_patterns(urlpatterns)
