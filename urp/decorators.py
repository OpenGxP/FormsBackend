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


def auth_required():
    """Authentication decorator to validate user authentication credentials."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if request.user.is_authenticated:
                return view_func(request, *args, **kwargs)
            return Response(status=status.HTTP_401_UNAUTHORIZED,
                            headers={'WWW-Authenticate': 'Bearer realm="api", charset="UTF-8"'})
        return wrapper
    return decorator


def perm_required(permissions):
    """Permission decorator to validate user permissions."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            for perm in permissions:
                if request.user.permission(perm):
                    return view_func(request, *args, **kwargs)
            return Response(status=status.HTTP_403_FORBIDDEN)
        return wrapper
    return decorator
