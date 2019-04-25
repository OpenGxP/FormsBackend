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
from django.conf import settings

# app imports
from ..models import LDAP
from ..serializers import LDAPReadWriteSerializer

# test imports
from . import Prerequisites, GetAll, PostNew, DeleteOneNoStatus, PatchOneNoStatus, GetOneNoStatus

# basic imports
from basics.custom import require_file


BASE_PATH = reverse('ldap-list')
LDAP_PASSWORD = require_file(path=settings.SECURITY_DIR + '/credentials/', file_name='LDAP_PASSWORD')


#############
# /md/ldap/ #
#############

# get
class GetAllLdap(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllLdap, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = LDAP
        self.serializer = LDAPReadWriteSerializer
        self.execute = True


class GetOneNoStatusLdap(GetOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(GetOneNoStatusLdap, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.model = LDAP
        self.serializer = LDAPReadWriteSerializer
        self.execute = True
        self.ok_object_data = {"host": "opengxp.com",
                               "port": 389,
                               "ssl_tls": False,
                               "bindDN": "cn=readonly,dc=opengxp,dc=com",
                               "password": LDAP_PASSWORD,
                               "base": "dc=opengxp,dc=com",
                               "filter": "(objectClass=inetOrgPerson)",
                               "attr_username": "uid",
                               "attr_email": "mail",
                               "attr_surname": "sn",
                               "attr_forename": "givenName",
                               "priority": 1}
        self.ok_object_data_unique = 'host'


# post
class PostNewLdap(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewLdap, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = LDAP
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = {"host": "opengxp.com",
                              "port": 389,
                              "ssl_tls": False,
                              "bindDN": "cn=readonly,dc=opengxp,dc=com",
                              "password": LDAP_PASSWORD,
                              "base": "dc=opengxp,dc=com",
                              "filter": "(objectClass=inetOrgPerson)",
                              "attr_username": "uid",
                              "attr_email": "mail",
                              "attr_surname": "sn",
                              "attr_forename": "givenName",
                              "priority": 1}
        self.invalid_payloads = [dict(),
                                 {"port": 389,
                                  "ssl_tls": False,
                                  "bindDN": "cn=readonly,dc=opengxp,dc=com",
                                  "password": LDAP_PASSWORD,
                                  "base": "dc=opengxp,dc=com",
                                  "filter": "(objectClass=inetOrgPerson)",
                                  "attr_username": "uid",
                                  "attr_email": "mail",
                                  "attr_surname": "sn",
                                  "attr_forename": "givenName",
                                  "priority": 1}
                                 ]
        self.execute = True
        self.status = False


# delete
class DeleteOneLdap(DeleteOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(DeleteOneLdap, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = LDAP
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = LDAPReadWriteSerializer
        self.ok_object_data = {"host": "opengxp.com",
                               "port": 389,
                               "ssl_tls": False,
                               "bindDN": "cn=readonly,dc=opengxp,dc=com",
                               "password": LDAP_PASSWORD,
                               "base": "dc=opengxp,dc=com",
                               "filter": "(objectClass=inetOrgPerson)",
                               "attr_username": "uid",
                               "attr_email": "mail",
                               "attr_surname": "sn",
                               "attr_forename": "givenName",
                               "priority": 1}
        self.ok_object_data_unique = 'host'
        self.execute = True


# patch
class PatchOneLdap(PatchOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneLdap, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = LDAP
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = LDAPReadWriteSerializer
        self.ok_object_data_unique = 'host'
        self.ok_object_data = {"host": "opengxp.com",
                               "port": 389,
                               "ssl_tls": False,
                               "bindDN": "cn=readonly,dc=opengxp,dc=com",
                               "password": LDAP_PASSWORD,
                               "base": "dc=opengxp,dc=com",
                               "filter": "(objectClass=inetOrgPerson)",
                               "attr_username": "uid",
                               "attr_email": "mail",
                               "attr_surname": "sn",
                               "attr_forename": "givenName",
                               "priority": 1}
        self.valid_payload = {"host": "opengxp.com",
                              "port": 389,
                              "ssl_tls": False,
                              "bindDN": "cn=readonly,dc=opengxp,dc=com",
                              "password": LDAP_PASSWORD,
                              "base": "dc=opengxp,dc=com",
                              "filter": "(objectClass=inetOrgPerson)",
                              "attr_username": "uid",
                              "attr_email": "mail",
                              "attr_surname": "sn",
                              "attr_forename": "givenName",
                              "priority": 2}
        self.invalid_payload = {"port": 389,
                                "ssl_tls": False,
                                "bindDN": "cn=readonly,dc=opengxp,dc=com",
                                "password": LDAP_PASSWORD,
                                "base": "dc=opengxp,dc=com",
                                "filter": "(objectClass=inetOrgPerson)",
                                "attr_username": "uid",
                                "attr_email": "mail",
                                "attr_surname": "sn",
                                "attr_forename": "givenName",
                                "priority": 1}
        self.execute = True
