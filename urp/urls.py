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

# app imports
from .views import permissions_list, status_list, roles_list, roles_detail, \
    roles_status, users_list, users_detail, api_root, users_status, access_log_list, central_log_list, \
    status_log_list, permissions_log_list, users_log_list, roles_log_list, audit_trail_list, \
    ldap_list, ldap_detail, ldap_log_list, login_view, logout_view, forms_list


urlpatterns = [
    # auth
    path('login', login_view, name='login-view'),
    path('logout', logout_view, name='logout-view'),
    # status
    path('md/status', status_list, name='status-list'),
    # permissions
    path('md/permissions', permissions_list, name='permissions-list'),
    # logs
    path('logs/central', central_log_list, name='central-log-list'),
    path('logs/access', access_log_list, name='access-log-list'),
    path('logs/status', status_log_list, name='status-log-list'),
    path('logs/permissions', permissions_log_list, name='permissions-log-list'),
    path('logs/roles', roles_log_list, name='roles-log-list'),
    path('logs/users', users_log_list, name='users-log-list'),
    path('logs/ldap', ldap_log_list, name='ldap-log-list'),
    # ldap
    path('md/ldap', ldap_list, name='ldap-list'),
    path('md/ldap/<str:host>', ldap_detail, name='ldap-detail'),
    # roles
    path('md/roles', roles_list, name='roles-list'),
    path('md/roles/<str:lifecycle_id>/<int:version>', roles_detail),
    path('md/roles/<str:lifecycle_id>/<int:version>/<str:status>', roles_status, name='roles-status'),
    # users
    path('md/users', users_list, name='users-list'),
    path('md/users/<str:lifecycle_id>/<int:version>', users_detail),
    path('md/users/<str:lifecycle_id>/<int:version>/<str:status>', users_status, name='users-status'),
    # root
    path('', api_root),
    # audit trails
    path('at/<str:dialog>/<str:lifecycle_id>', audit_trail_list, name='audit-trail-list'),
    # form views
    path('form/<str:dialog>', forms_list, name='forms-list')
]
