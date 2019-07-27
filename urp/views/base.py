"""
opengxp.org
Copyright (C) 2019 Henrik Baran

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
from functools import wraps

# rest imports
from rest_framework.response import Response
from rest_framework import status as http_status

# app imports
from basics.models import Settings
from urp.backends.User import write_access_log

# django imports
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import logout


def refresh_time(request, active=True):
    now = timezone.now()
    if now - request.session['last_touch'] > timezone.timedelta(minutes=Settings.objects.core_auto_logout):
        data = {
            'user': request.user.username,
            'timestamp': now,
            'mode': 'automatic',
            'method': Settings.objects.core_devalue,
            'action': settings.DEFAULT_LOG_LOGOUT,
            'attempt': Settings.objects.core_devalue,
            'active': Settings.objects.core_devalue
        }
        logout(request)
        if request.user.is_anonymous:
            write_access_log(data)
    else:
        # only refresh if user was active (default for request)
        if active:
            request.session['last_touch'] = now
        return True


def auto_logout():
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # use method
            if refresh_time(request=request):
                return view_func(request, *args, **kwargs)
            else:
                return Response(status=http_status.HTTP_401_UNAUTHORIZED)
        return wrapper
    return decorator
