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
from rest_framework import routers

# django imports
from django.conf.urls import url, include

# app imports
from .views import StatusViewSet, index, PermissionsViewSet, UsersViewSet, RolesViewSet


router = routers.DefaultRouter()
router.register(r'status', StatusViewSet)
router.register(r'permissions', PermissionsViewSet)
router.register(r'users', UsersViewSet)
router.register(r'roles', RolesViewSet)

urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^index', index, name='index')
]
