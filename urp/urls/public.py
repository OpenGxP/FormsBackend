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

# django imports
from django.urls import path
from django.conf import settings

# app imports
from urp.views.public.root import public_root_view
from urp.views.public.login import login_view
from urp.views.public.password_reset import request_password_reset_email_view, password_reset_email_view


urls_public = [
    # root
    path('{}'.format(settings.BASE_URL), public_root_view, name='public-root-view'),
    # endpoints
    path('{}login'.format(settings.BASE_URL), login_view, name='login-view'),
    path('{}request_password_reset_email'.format(settings.BASE_URL), request_password_reset_email_view,
         name='request-password-reset-email-view'),
    path('{}password_reset_email/<str:token>'.format(settings.BASE_URL), password_reset_email_view,
         name='password-reset-email-view'),
]
