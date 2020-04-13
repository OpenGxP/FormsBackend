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

# python imports
from functools import wraps

# rest imports
from rest_framework.response import Response

# app imports
from .models import Roles, LDAP, Users, SoD, Email
from urp.models.profile import Profile
from basics.models import Settings
from urp.checks import Check


def auth_required(initial_password_check=True):
    """Authentication decorator to validate user authentication credentials."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # external users
            if getattr(request.user, 'external', False):
                check = Check(request=request, username=request.user.username, opt_filter_user={'external': True},
                              initial_password_check=False, ext=True)
                if not check.verify_overall():
                    return Response(status=check.http_status)
                return view_func(request, *args, **kwargs)
            # internal users
            else:
                check = Check(request=request, username=request.user.username, opt_filter_user={'external': False},
                              initial_password_check=initial_password_check)
                if not check.verify_overall():
                    return Response(status=check.http_status)
                return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def perm_required(permission):
    """Authorisation decorator to validate permission of authenticated user."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            check = Check(request=request)
            if not check.verify_permission(permission=permission):
                return Response(status=check.http_status)
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def auth_perm_required(permission, initial_password_check=True):
    """Authentication and permission decorator"""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # external users
            if getattr(request.user, 'external', False):
                check = Check(request=request, username=request.user.username, opt_filter_user={'external': True},
                              initial_password_check=False, ext=True)
                if not check.verify_overall(permission=permission):
                    return Response(status=check.http_status)
                return view_func(request, *args, **kwargs)
            # internal users
            else:
                check = Check(request=request, username=request.user.username, opt_filter_user={'external': False},
                              initial_password_check=initial_password_check)
                if not check.verify_overall(permission=permission):
                    return Response(status=check.http_status)
                return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_http_method(http_method):
    """Decorator to check http_method of validate method in serializer class."""
    def decorator(func):
        @wraps(func)
        def wrapper(validate_method, *args, **kwargs):
            if validate_method.context['method'] == http_method:
                return func(validate_method, *args, **kwargs)
        return wrapper
    return decorator


require_GET = require_http_method('GET')
require_PATCH = require_http_method('PATCH')
require_POST = require_http_method('POST')
require_DELETE = require_http_method('DELETE')
require_PUT = require_http_method('PUT')


def require_function(required_function):
    """Decorator."""
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if self.function == required_function:
                return func(self, *args, **kwargs)
        return wrapper
    return decorator


require_STATUS_CHANGE = require_function('status_change')
require_NEW_VERSION = require_function('new_version')
require_NONE = require_function('')
require_NEW = require_function('new')


def require_model(model):
    """Decorator."""
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if self.model == model:
                return func(self, *args, **kwargs)
        return wrapper
    return decorator


require_ROLES = require_model(Roles)
require_LDAP = require_model(LDAP)
require_USERS = require_model(Users)
require_SETTINGS = require_model(Settings)
require_SOD = require_model(SoD)
require_EMAIL = require_model(Email)
require_PROFILE = require_model(Profile)


def require_status(_status):
    """Decorator."""
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if self.instance.status.id == _status:
                return func(self, *args, **kwargs)
        return wrapper
    return decorator
