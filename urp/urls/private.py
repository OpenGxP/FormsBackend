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

# django imports
from django.urls import path
from django.conf import settings

# app imports
from urp.views.private.root import private_root_view
from urp.views.private.inbox import inbox_list, inbox_notifications
from urp.views.private.profile import profile_detail, profile_list, profile_log_list, set_timezone_view
from urp.views.private.forms import forms_list, forms_detail, forms_status, forms_log_list, forms_sections_log_list, \
    forms_bool_fields_log_list, forms_text_fields_log_list, forms_list_validate, forms_detail_validate
from urp.views.private.workflows import workflows_list, workflows_detail, workflows_status, \
    workflows_log_list, workflows_steps_log_list, workflows_list_validate, workflows_detail_validate
from urp.views.private.logs.signatures import signatures_log_list
from urp.views.private.execution import execution_list, execution_detail, execution_log_list, execution_status, \
    execution_value, list_log_value
from urp.views.private.roles import roles_list, roles_detail, roles_ldap, roles_log_list, roles_status, \
    roles_detail_validate, roles_list_validate
from urp.views.private.tags import tags_list, tags_list_validate, tags_detail, tags_detail_validate, tags_log_list
from urp.views.private.users import users_list, users_detail, users_status, users_log_list, users_detail_validate, \
    users_list_validate
from urp.views.private.ldap import ldap_list, ldap_detail, ldap_log_list, ldap_list_validate, ldap_detail_validate
from urp.views.private.spaces import spaces_list, spaces_detail, spaces_log_list, spaces_list_validate, \
    spaces_detail_validate
from urp.views.private.lists import lists_list, lists_detail, lists_log_list, lists_status, lists_list_validate, \
    lists_detail_validate
from urp.views.private.email import email_detail, email_list, email_log_list, email_list_validate, email_detail_validate
from urp.views.private.settings import settings_list, settings_detail, settings_log_list, settings_detail_validate
from urp.views.private.sod import sod_list, sod_detail, sod_log_list, sod_status, sod_list_validate, sod_detail_validate
from urp.views.private.webhooks import webhooks_list, webhooks_detail, webhooks_log_list, webhooks_status, \
    webhooks_list_validate, webhooks_detail_validate
from urp.views.private.securitykeys import securitykeys_list, securitykeys_detail, securitykeys_log_list, \
    securitykeys_list_validate
from urp.views.private.webhooksmonitor import webhooksmonitor_list, webhooksmonitor_log_list

# app imports
from urp.views import permissions_list, status_list, access_log_list, central_log_list, \
    permissions_log_list, status_log_list, logout_view, meta_list, get_csrf_token, logout_auto_view, \
    users_password_list, change_password_view, user_change_password_view, user_change_questions_view, \
    user_profile_list

urls_private = [
    # root
    path('{}_root'.format(settings.BASE_URL), private_root_view, name='private-root-view'),
    # auth
    path('{}csrftoken'.format(settings.BASE_URL), get_csrf_token, name='get_csrf_token'),
    path('{}logout'.format(settings.BASE_URL), logout_view, name='logout-view'),
    path('{}logout_auto'.format(settings.BASE_URL), logout_auto_view, name='logout-auto-view'),
    # user profile
    path('{}user/profile_questions'.format(settings.BASE_URL), user_profile_list,
         name='user-profile-list'),
    path('{}user/change_questions'.format(settings.BASE_URL), user_change_questions_view,
         name='user-change-questions-view'),
    path('{}user/change_password'.format(settings.BASE_URL), user_change_password_view,
         name='user-change-password-view'),
    # inbox
    path('{}user/inbox'.format(settings.BASE_URL), inbox_list, name='inbox-list'),
    # FO-240: helper view for inbox notification polling only
    path('{}user/inbox/notifications'.format(settings.BASE_URL), inbox_notifications, name='inbox-notifications'),
    # general user profile
    path('{}user/profile'.format(settings.BASE_URL), profile_list, name='profile-list'),
    path('{}user/profile/<str:key>'.format(settings.BASE_URL), profile_detail, name='profile-detail'),
    path('{}user/set_timezone'.format(settings.BASE_URL), set_timezone_view, name='set-timezone-view'),
    # status
    path('{}admin/status'.format(settings.BASE_URL), status_list, name='status-list'),
    # permissions
    path('{}admin/permissions'.format(settings.BASE_URL), permissions_list, name='permissions-list'),
    # logs
    path('{}logs/central'.format(settings.BASE_URL), central_log_list, name='central-log-list'),
    path('{}logs/access'.format(settings.BASE_URL), access_log_list, name='access-log-list'),
    path('{}logs/signatures'.format(settings.BASE_URL), signatures_log_list, name='signatures-log-list'),
    path('{}logs/status'.format(settings.BASE_URL), status_log_list, name='status-log-list'),
    path('{}logs/permissions'.format(settings.BASE_URL), permissions_log_list, name='permissions-log-list'),
    path('{}logs/roles'.format(settings.BASE_URL), roles_log_list, name='roles-log-list'),
    path('{}logs/users'.format(settings.BASE_URL), users_log_list, name='users-log-list'),
    path('{}logs/webhooks'.format(settings.BASE_URL), webhooks_log_list, name='webhooks-log-list'),
    path('{}logs/sod'.format(settings.BASE_URL), sod_log_list, name='sod-log-list'),
    path('{}logs/ldap'.format(settings.BASE_URL), ldap_log_list, name='ldap-log-list'),
    path('{}logs/email'.format(settings.BASE_URL), email_log_list, name='email-log-list'),
    path('{}logs/settings'.format(settings.BASE_URL), settings_log_list, name='settings-log-list'),
    path('{}logs/securitykeys'.format(settings.BASE_URL), securitykeys_log_list, name='securitykeys-log-list'),
    path('{}logs/tags'.format(settings.BASE_URL), tags_log_list, name='tags-log-list'),
    path('{}logs/spaces'.format(settings.BASE_URL), spaces_log_list, name='spaces-log-list'),
    path('{}logs/lists'.format(settings.BASE_URL), lists_log_list, name='lists-log-list'),
    path('{}logs/workflows'.format(settings.BASE_URL), workflows_log_list, name='workflows-log-list'),
    path('{}logs/workflows_steps'.format(settings.BASE_URL), workflows_steps_log_list, name='workflows-steps-log-list'),
    path('{}logs/forms'.format(settings.BASE_URL), forms_log_list, name='forms-log-list'),
    path('{}logs/forms_sections'.format(settings.BASE_URL), forms_sections_log_list, name='forms-sections-log-list'),
    path('{}logs/forms_text_fields'.format(settings.BASE_URL), forms_text_fields_log_list,
         name='forms-text-fields-log-list'),
    path('{}logs/forms_bool_fields'.format(settings.BASE_URL), forms_bool_fields_log_list,
         name='forms-bool-fields-log-list'),
    path('{}logs/profile'.format(settings.BASE_URL), profile_log_list, name='profile-log-list'),
    path('{}logs/execution'.format(settings.BASE_URL), execution_log_list, name='execution-log-list'),
    path('{}logs/execution_values'.format(settings.BASE_URL), list_log_value, name='execution-values-log-list'),
    path('{}logs/webhooksmonitor'.format(settings.BASE_URL), webhooksmonitor_log_list, name='webhooksmonitor-log-list'),
    # ldap
    path('{}admin/ldap'.format(settings.BASE_URL), ldap_list, name='ldap-list'),
    path('{}admin/ldap_validate'.format(settings.BASE_URL), ldap_list_validate, name='ldap-list-validate'),
    path('{}admin/ldap/<str:host>'.format(settings.BASE_URL), ldap_detail, name='ldap-detail'),
    path('{}admin/ldap_validate/<str:host>'.format(settings.BASE_URL), ldap_detail_validate,
         name='ldap-detail-validate'),
    # tags
    path('{}admin/tags'.format(settings.BASE_URL), tags_list, name='tags-list'),
    path('{}admin/tags_validate'.format(settings.BASE_URL), tags_list_validate, name='tags-list-validate'),
    path('{}admin/tags/<str:tag>'.format(settings.BASE_URL), tags_detail, name='tags-detail'),
    path('{}admin/tags_validate/<str:tag>'.format(settings.BASE_URL), tags_detail_validate,
         name='tags-detail-validate'),
    # spaces
    path('{}admin/spaces'.format(settings.BASE_URL), spaces_list, name='spaces-list'),
    path('{}admin/spaces_validate'.format(settings.BASE_URL), spaces_list_validate, name='spaces-list-validate'),
    path('{}admin/spaces/<str:space>'.format(settings.BASE_URL), spaces_detail, name='spaces-detail'),
    path('{}admin/spaces_validate/<str:space>'.format(settings.BASE_URL), spaces_detail_validate,
         name='spaces-detail-validate'),
    # email
    path('{}admin/email'.format(settings.BASE_URL), email_list, name='email-list'),
    path('{}admin/email_validate'.format(settings.BASE_URL), email_list_validate, name='email-list-validate'),
    path('{}admin/email/<str:host>'.format(settings.BASE_URL), email_detail, name='email-detail'),
    path('{}admin/email_validate/<str:host>'.format(settings.BASE_URL), email_detail_validate,
         name='email-detail-validate'),
    # settings
    path('{}admin/settings'.format(settings.BASE_URL), settings_list, name='settings-list'),
    path('{}admin/settings/<str:key>'.format(settings.BASE_URL), settings_detail, name='settings-detail'),
    path('{}admin/settings_validate/<str:key>'.format(settings.BASE_URL), settings_detail_validate,
         name='settings-detail-validate'),
    # security keys
    path('{}admin/securitykeys'.format(settings.BASE_URL), securitykeys_list, name='securitykeys-list'),
    path('{}admin/securitykeys_validate'.format(settings.BASE_URL), securitykeys_list_validate,
         name='securitykeys-list-validate'),
    path('{}admin/securitykeys/<str:security_key>'.format(settings.BASE_URL), securitykeys_detail,
         name='securitykeys-detail'),
    # webhooksmonitor
    path('{}admin/webhooksmonitor'.format(settings.BASE_URL), webhooksmonitor_list, name='webhooksmonitor-list'),
    # roles
    path('{}admin/roles'.format(settings.BASE_URL), roles_list, name='roles-list'),
    path('{}admin/roles_validate'.format(settings.BASE_URL), roles_list_validate, name='roles-list-validate'),
    path('{}admin/roles/ldap'.format(settings.BASE_URL), roles_ldap, name='roles-ldap'),
    path('{}admin/roles/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), roles_detail),
    path('{}admin/roles_validate/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), roles_detail_validate,
         name='roles-detail-validate'),
    path('{}admin/roles/<str:lifecycle_id>/<int:version>/<str:status>'.format(settings.BASE_URL), roles_status,
         name='roles-status'),
    # sod
    path('{}admin/sod'.format(settings.BASE_URL), sod_list, name='sod-list'),
    path('{}admin/sod_validate'.format(settings.BASE_URL), sod_list_validate, name='sod-list-validate'),
    path('{}admin/sod/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), sod_detail),
    path('{}admin/sod_validate/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), sod_detail_validate,
         name='sod-detail-validate'),
    path('{}admin/sod/<str:lifecycle_id>/<int:version>/<str:status>'.format(settings.BASE_URL), sod_status,
         name='sod-status'),
    # users
    path('{}admin/users'.format(settings.BASE_URL), users_list, name='users-list'),
    path('{}admin/users_validate'.format(settings.BASE_URL), users_list_validate, name='users-list-validate'),
    path('{}admin/users/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), users_detail),
    path('{}admin/users_validate/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), users_detail_validate,
         name='users-detail-validate'),
    path('{}admin/users/<str:lifecycle_id>/<int:version>/<str:status>'.format(settings.BASE_URL), users_status,
         name='users-status'),
    path('{}admin/passwords'.format(settings.BASE_URL), users_password_list, name='users-password-list'),
    path('{}admin/passwords/<str:username>'.format(settings.BASE_URL), change_password_view,
         name='change-password-view'),
    # webhooks
    path('{}admin/webhooks'.format(settings.BASE_URL), webhooks_list, name='webhooks-list'),
    path('{}admin/webhooks_validate'.format(settings.BASE_URL), webhooks_list_validate, name='webhooks-list-validate'),
    path('{}admin/webhooks/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), webhooks_detail,
         name='webhooks-detail'),
    path('{}admin/webhooks_validate/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL),
         webhooks_detail_validate, name='webhooks-detail-validate'),
    path('{}admin/webhooks/<str:lifecycle_id>/<int:version>/<str:status>'.format(settings.BASE_URL), webhooks_status,
         name='webhooks-status'),
    # lists
    path('{}md/lists'.format(settings.BASE_URL), lists_list, name='lists-list'),
    path('{}md/lists_validate'.format(settings.BASE_URL), lists_list_validate, name='lists-list-validate'),
    path('{}md/lists/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), lists_detail),
    path('{}md/lists_validate/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), lists_detail_validate,
         name='lists-detail-validate'),
    path('{}md/lists/<str:lifecycle_id>/<int:version>/<str:status>'.format(settings.BASE_URL), lists_status,
         name='lists-status'),
    # workflows
    path('{}md/workflows'.format(settings.BASE_URL), workflows_list, name='workflows-list'),
    path('{}md/workflows_validate'.format(settings.BASE_URL), workflows_list_validate, name='workflows-list-validate'),
    path('{}md/workflows/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), workflows_detail),
    path('{}md/workflows_validate/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL),
         workflows_detail_validate, name='workflows-detail-validate'),
    path('{}md/workflows/<str:lifecycle_id>/<int:version>/<str:status>'.format(settings.BASE_URL), workflows_status,
         name='workflows-status'),
    # forms
    path('{}md/forms'.format(settings.BASE_URL), forms_list, name='forms-list'),
    path('{}md/forms_validate'.format(settings.BASE_URL), forms_list_validate, name='forms-list-validate'),
    path('{}md/forms/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), forms_detail),
    path('{}md/forms_validate/<str:lifecycle_id>/<int:version>'.format(settings.BASE_URL), forms_detail_validate,
         name='forms-detail-validate'),
    path('{}md/forms/<str:lifecycle_id>/<int:version>/<str:status>'.format(settings.BASE_URL), forms_status,
         name='forms-status'),
    # execution
    path('{}rtd/execution'.format(settings.BASE_URL), execution_list, name='execution-list'),
    path('{}rtd/execution/<int:number>'.format(settings.BASE_URL), execution_detail),
    path('{}rtd/execution/<int:number>/<str:status>'.format(settings.BASE_URL), execution_status,
         name='forms-status'),
    path('{}rtd/execution/<int:number>/<str:section>/<str:field>'.format(settings.BASE_URL),
         execution_value, name='execution-value'),
    # meta views
    path('{}meta/<str:dialog>'.format(settings.BASE_URL), meta_list, name='meta-list'),
]
