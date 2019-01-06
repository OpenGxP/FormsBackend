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

# django imports
from django.urls import reverse

# app imports
from ..models import Status
from ..serializers import StatusReadWriteSerializer

# test imports
from . import Get


############
# /status/ #
############

# get
class GetStatus(Get):
    def __init__(self, *args, **kwargs):
        super(GetStatus, self).__init__(*args, **kwargs)
        self.path = reverse('status-list')
        self.model = Status
        self.serializer = StatusReadWriteSerializer
        self.execute = True

    def test_200_csrf(self):
        pass
