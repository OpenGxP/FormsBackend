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
from django.conf import settings

# rest imports
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.reverse import reverse


@api_view(['GET'])
def public_root_view(request):
    root = {'login': {'url': {'abs': reverse('login-view', request=request),
                              'rel': '{}login'.format(settings.BASE_URL)}},
            'request_password_reset_email': {'url': {'abs': reverse('request-password-reset-email-view',
                                                                    request=request),
                                                     'rel': '{}request_password_reset_email'.format(
                                                         settings.BASE_URL)}},
            'password_reset_email': {'url': {'abs': '',
                                             'rel': '{}password_reset_email/<str:token>'.format(settings.BASE_URL)}},
            '_root': {'url': {'abs': reverse('private-root-view', request=request),
                              'rel': '{}_root'.format(settings.BASE_URL)}}}

    return Response(root)
