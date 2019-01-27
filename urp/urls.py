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
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView

# django imports
from django.urls import path

# app imports
from .views import permissions_list, status_list, roles_list, roles_detail, \
    roles_status, users_list, users_detail, api_root


urlpatterns = [
    # status
    path('status/', status_list, name='status-list'),
    # path('status/<int:pk>/', status_detail),
    # permissions
    path('permissions/', permissions_list, name='permissions-list'),
    # path('permissions/<int:pk>/', permissions_detail),
    # roles
    path('roles/', roles_list, name='roles-list'),
    path('roles/<str:lifecycle_id>/<int:version>', roles_detail),
    path('roles/<str:lifecycle_id>/<int:version>/<str:status>', roles_status, name='roles-status'),
    # users
    path('users/', users_list, name='users-list'),
    path('users/<str:lifecycle_id>/<int:version>', users_detail),
    # root
    path('', api_root),
    # authentication JWT
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
]

urlpatterns = format_suffix_patterns(urlpatterns)
