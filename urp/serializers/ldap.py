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

# app imports
from urp.models.ldap import LDAP, LDAPLog
from urp.serializers import GlobalReadWriteSerializer


# read / add / edit
class LDAPReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = LDAP
        extra_kwargs = {'password': {'write_only': True}}
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_CALCULATED


# delete
class LDAPDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = LDAP
        fields = ()


# read logs
class LDAPLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = LDAPLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
