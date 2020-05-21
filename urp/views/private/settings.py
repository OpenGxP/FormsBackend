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

# rest imports
from rest_framework.decorators import api_view

# custom imports
from urp.serializers.settings import SettingsLogReadSerializer, SettingsReadWriteSerializer
from urp.decorators import auth_required, auth_auth_required
from urp.models.settings import Settings
from urp.views.base import auto_logout, UpdateView


view = UpdateView(model=Settings, ser_rw=SettingsReadWriteSerializer, ser_log=SettingsLogReadSerializer)


@api_view(['GET'])
@auth_required()
@auto_logout()
def settings_list(request):
    return view.list(request)


@api_view(['GET', 'PATCH'])
@auth_required()
@auto_logout()
def settings_detail(request, key):
    return view.detail(request, key)


@api_view(['PATCH'])
@auth_auth_required()
@auto_logout()
def settings_detail_validate(request, key):
    return view.detail(request, key, validate_only=True)


@api_view(['GET'])
@auth_required()
@auto_logout()
def settings_log_list(request):
    return view.list_log(request)
