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
from rest_framework import status

# app imports
from .models import Roles, LDAP, Users, SoD
from basics.models import Settings


def auth_required():
    """Authentication decorator to validate user authentication credentials."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # FO-121: add second requirement, user must be prod and valid
            if request.user.is_authenticated and Users.objects.verify_prod_valid(key=request.user.username) \
                    and request.user.verify_sod:
                return view_func(request, *args, **kwargs)
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        return wrapper
    return decorator


def perm_required(permission):
    """Permission decorator to validate user permissions."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if request.user.permission(permission):
                return view_func(request, *args, **kwargs)
            return Response(status=status.HTTP_403_FORBIDDEN)
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


def require_status(_status):
    """Decorator."""
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if self.instance.status.id == _status:
                return func(self, *args, **kwargs)
        return wrapper
    return decorator
