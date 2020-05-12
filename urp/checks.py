"""
opengxp.org
Copyright (C) 2020 Henrik Baran

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

# python import
import itertools

# django imports
from django.utils import timezone
from django.db.models import Q
from django.conf import settings

# app imports
from urp.models.users import Users
from urp.models.roles import Roles
from basics.models import Status
from urp.models.sod import SoD
from urp.models.ldap import LDAP
from urp.models.permissions import Permissions

# rest imports
from rest_framework import status as http_status


class Check(object):
    def __init__(self, request, username=None, ext_users=None, opt_filter_user=None, opt_filter_roles=None,
                 initial_password_check=True, public=False, ext=None):
        # handle now
        now = getattr(request, settings.ATTR_NOW, None)
        if not now:
            now = timezone.now()
            setattr(request, settings.ATTR_NOW, now)
        self.now = now
        setattr(request, settings.ATTR_NOW, now)
        # others
        self.request = request
        self.user_prod = None
        self.user = None
        self.roles = []
        self.http_status = None
        self.error = None
        self.ext = ext
        self.public = public
        self.username = username
        self.ext_users = ext_users
        self.opt_filter_user = opt_filter_user
        self.opt_filter_roles = opt_filter_roles
        self.initial_password_check = initial_password_check

    def verify_overall(self, permission=None):
        # 0) verify not anonymous, but authenticated
        if not self.verify_authentication:
            return False
        # 1) verify that user is ok
        if self.ext:
            if not self.verify_ext_user:
                self.http_status = http_status.HTTP_401_UNAUTHORIZED
                return False
        else:
            if not self.verify_user:
                self.http_status = http_status.HTTP_401_UNAUTHORIZED
                return False
        # 2) if initial password check, verify that no initial password is set
        if self.initial_password_check:
            if not self.initial_password:
                self.http_status = http_status.HTTP_401_UNAUTHORIZED
                return False
        # 3) verify that user has at least one valid role
        if self.ext:
            if not self.verify_ext_roles:
                self.http_status = http_status.HTTP_401_UNAUTHORIZED
                return False
        else:
            if not self.verify_roles:
                self.http_status = http_status.HTTP_401_UNAUTHORIZED
                return False
        # 4) verify that valid roles are not in sod conflict
        if not self.verify_sod:
            self.http_status = http_status.HTTP_401_UNAUTHORIZED
            return False
        # 5) if permission check, verify that valid roles contain permission
        if permission:
            if not self.verify_permission(permission=permission):
                return False
        # 6) if public, add casl object
        if self.public:
            self.casl()
        return True

    @property
    def verify_authentication(self):
        # return True for public authenticate use like login
        if self.public:
            setattr(self.request, settings.ATTR_AUTH, True)
            return True
        if not self.request.user.is_authenticated:
            self.http_status = http_status.HTTP_401_UNAUTHORIZED
            return False
        setattr(self.request, settings.ATTR_AUTH, True)
        return True

    @property
    def verify_user(self):
        self.user, self.error = Users.objects.prod_val_with_errors(key=self.username, opt_filter=self.opt_filter_user,
                                                                   now=self.now)
        if self.user:
            # FO-273: set user, that is the prod valid on every request
            setattr(self.request, 'user', self.user)
        return self.user

    @property
    def verify_ext_user(self):
        self.user, self.error = Users.objects.prod_val_with_errors(key=self.username, opt_filter=self.opt_filter_user,
                                                                   now=self.now)
        # for login / public
        if self.public:
            # this means no record at all exist, so create new record
            if self.error == settings.ERROR_NO_RECORD:
                self.user = Users.objects.create_ldap_external_user(username=self.username, now=self.now)
        if self.user:
            # FO-273: set user, that is the prod valid on every request
            setattr(self.request, 'user', self.user)
        return self.user

    @property
    def initial_password(self):
        if self.user.initial_password:
            return False
        setattr(self.request, settings.ATTR_INITIAL_PW, True)
        return True

    @property
    def verify_roles(self):
        # get all valid roles for further use (sod and casl), for this check one is ok
        _roles = []
        _user_roles = self.user.roles_list
        query = Roles.objects.get_prod_valid_list(opt_filter=self.opt_filter_roles, now=self.now)
        for item in query:
            if item.role in _user_roles:
                _roles.append(item)
        self.roles = _roles
        setattr(self.request, settings.ATTR_ROLES, _roles)
        return self.roles

    @property
    def verify_ext_roles(self):
        # get all valid roles for further use (sod and casl), for this check one is ok
        _roles = []
        response = LDAP.objects.get_group_membership(username=self.username)
        for item in response:
            valid_prod_role = Roles.objects.verify_prod_valid(key=item, opt_filter={'ldap': True}, now=self.now)
            if valid_prod_role:
                _roles.append(valid_prod_role)
        self.roles = _roles
        setattr(self.request, settings.ATTR_ROLES, _roles)
        return self.roles

    def verify_permission(self, permission):
        # FO-235: if no permission passed / required, return True
        if not permission:
            setattr(self.request, settings.ATTR_PERMISSION, True)
            return True
        if getattr(self.request, settings.ATTR_ROLES, None):
            _roles = getattr(self.request, settings.ATTR_ROLES)
        else:
            _roles = self.roles
        for role in _roles:
            # check each role for the requested permission
            if any(perm in role.permissions.split(',') for perm in [permission, settings.ALL_PERMISSIONS]):
                setattr(self.request, settings.ATTR_PERMISSION, True)
                return True
        self.http_status = http_status.HTTP_403_FORBIDDEN
        return False

    @property
    def verify_sod(self):
        # get role names
        _roles_names = []
        for role in self.roles:
            _roles_names.append(getattr(role, Roles.UNIQUE, ''))
        # determine pairs of roles
        combinations = itertools.combinations(_roles_names, 2)
        status_effective_id = Status.objects.productive
        # parse combinations
        for a, b in combinations:
            # look for productive sod records
            query = SoD.objects.filter(Q(base=a, conflict=b, status__id=status_effective_id) |
                                       Q(base=b, conflict=a, status__id=status_effective_id)).all()
            # check if records are valid
            for record in query:
                if record.verify_validity_range(now=self.now):
                    return False
        setattr(self.request, settings.ATTR_SOD, True)
        return True

    def casl(self):
        permissions = []
        # parse over valid roles and
        for role in self.roles:
            permissions = list(set(permissions + role.permissions.split(',')))
        casl = []
        # iterate merges permissions to build casl response
        for perm in permissions:
            # FO-149: skip empty permissions
            try:
                perm_obj = Permissions.objects.filter(key=perm).get()
            except Permissions.DoesNotExist:
                continue
            append = None
            # check if subject exists and add if yes
            for item in casl:
                if item['subject'][0] == perm_obj.model:
                    item['actions'].append(perm_obj.permission)
                    append = True
            if not append:
                # append permission to new subject
                casl.append({'subject': [perm_obj.model],
                             'actions': [perm_obj.permission]})
        setattr(self.request, settings.ATTR_CASL, casl)
        return casl
