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
from urp.serializers.logs.signatures import SignaturesLogReadWriteSerializer
from urp.decorators import perm_required, auth_required
from urp.models.logs.signatures import SignaturesLog
from urp.views.base import auto_logout, GET


# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(SignaturesLog.MODEL_ID))
def signatures_log_list(request):
    get = GET(model=SignaturesLog, request=request, serializer=SignaturesLogReadWriteSerializer)
    return get.standard
