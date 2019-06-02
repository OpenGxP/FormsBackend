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


# django imports
from django.urls import path
from django.conf import settings

# app imports
from .views import permissions_list, roles_list, roles_detail, status_list, \
    roles_status, users_list, users_detail, api_root, users_status, access_log_list, central_log_list, \
    permissions_log_list, users_log_list, roles_log_list, audit_trail_list, status_log_list, \
    ldap_list, ldap_detail, ldap_log_list, login_view, logout_view, meta_list, get_csrf_token, settings_list, \
    settings_detail, settings_log_list, logout_auto_view, sod_list, sod_detail, sod_log_list, sod_status, \
    users_password_list, change_password_view, self_change_password_view


urlpatterns = [
    # auth
    path('{}login'.format(settings.BASE_URL), login_view, name='login-view'),
    path('{}csrftoken'.format(settings.BASE_URL), get_csrf_token, name='get_csrf_token'),
    path('{}logout'.format(settings.BASE_URL), logout_view, name='logout-view'),
    path('{}logout_auto'.format(settings.BASE_URL), logout_auto_view, name='logout-auto-view'),
    path('{}self_change_password'.format(settings.BASE_URL), self_change_password_view,
         name='self-change-password-view'),
    # status
    path('{}admin/status'.format(settings.BASE_URL), status_list, name='status-list'),
    # permissions
    path('{}admin/permissions'.format(settings.BASE_URL), permissions_list, name='permissions-list'),
    # logs
    path('{}logs/central'.format(settings.BASE_URL), central_log_list, name='central-log-list'),
    path('{}logs/access'.format(settings.BASE_URL), access_log_list, name='access-log-list'),
    path('{}logs/status'.format(settings.BASE_URL), status_log_list, name='status-log-list'),
    path('{}logs/permissions'.format(settings.BASE_URL), permissions_log_list, name='permissions-log-list'),
    path('{}logs/roles'.format(settings.BASE_URL), roles_log_list, name='roles-log-list'),
    path('{}logs/users'.format(settings.BASE_URL), users_log_list, name='users-log-list'),
    path('{}logs/sod'.format(settings.BASE_URL), sod_log_list, name='sod-log-list'),
    path('{}logs/ldap'.format(settings.BASE_URL), ldap_log_list, name='ldap-log-list'),
    path('{}logs/settings'.format(settings.BASE_URL), settings_log_list, name='settings-log-list'),
    # ldap
    path('{}admin/ldap'.format(settings.BASE_URL), ldap_list, name='ldap-list'),
    path('{}admin/ldap/<str:host>'.format(settings.BASE_URL), ldap_detail, name='ldap-detail'),
    # settings
    path('{}admin/settings'.format(settings.BASE_URL), settings_list, name='settings-list'),
    path('{}admin/settings/<str:key>'.format(settings.BASE_URL), settings_detail, name='settings-detail'),
    # roles
    path('{}admin/roles'.format(settings.BASE_URL), roles_list, name='roles-list'),
    path('{}admin/roles/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), roles_detail),
    path('{}admin/roles/<str:lifecycle_id>/<int:version>/<str:status>'.format(settings.BASE_URL), roles_status,
         name='roles-status'),
    # sod
    path('{}admin/sod'.format(settings.BASE_URL), sod_list, name='sod-list'),
    path('{}admin/sod/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), sod_detail),
    path('{}admin/sod/<str:lifecycle_id>/<int:version>/<str:status>'.format(settings.BASE_URL), sod_status,
         name='sod-status'),
    # users
    path('{}admin/users'.format(settings.BASE_URL), users_list, name='users-list'),
    path('{}admin/users/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), users_detail),
    path('{}admin/users/<str:lifecycle_id>/<int:version>/<str:status>'.format(settings.BASE_URL), users_status,
         name='users-status'),
    # users passwords
    path('{}admin/users_password'.format(settings.BASE_URL), users_password_list, name='users-password-list'),
    path('{}admin/change_password/<str:username>'.format(settings.BASE_URL), change_password_view,
         name='change-password-view'),
    # root
    path('{}'.format(settings.BASE_URL[:-1]), api_root),
    # audit trails
    path('{}at/<str:dialog>/<str:lifecycle_id>'.format(settings.BASE_URL), audit_trail_list, name='audit-trail-list'),
    # meta views
    path('{}meta/<str:dialog>'.format(settings.BASE_URL), meta_list, name='meta-list')
]
