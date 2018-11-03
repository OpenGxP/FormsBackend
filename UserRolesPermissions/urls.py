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
from django.urls import path

# app imports
from .views import permissions_list, permissions_detail, status_list, status_detail, roles_list, roles_detail, \
    users_list, users_detail, api_root


urlpatterns = [
    # status
    path('status/', status_list, name='status-list'),
    path('status/<int:pk>/', status_detail),
    # permissions
    path('permissions/', permissions_list, name='permissions-list'),
    path('permissions/<int:pk>/', permissions_detail),
    # roles
    path('roles/', roles_list, name='roles-list'),
    path('roles/<int:pk>/', roles_detail),
    # users
    path('users/', users_list, name='users-list'),
    path('users/<int:pk>/', users_detail),
    # root
    path('', api_root),
]

urlpatterns = format_suffix_patterns(urlpatterns)
