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

# django imports
from django.db import models
from django.db.models import Q
from django.conf import settings
from django.utils.translation import gettext_lazy as _

# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, Status, LOG_HASH_SEQUENCE, FIELD_VERSION, \
    CHAR_BIG, GlobalModelLog
from urp.validators import validate_no_space, validate_no_specials_reduced, SPECIALS_REDUCED, \
    validate_no_numbers, validate_only_ascii
from urp.models.permissions import Permissions


# log manager
class RolesLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('role',
                       'ldap',
                       'permissions')


# log table
class RolesLog(GlobalModelLog):
    # custom fields
    role = models.CharField(_('Role'), max_length=CHAR_DEFAULT)
    permissions = models.CharField(_('Permissions'), max_length=CHAR_BIG, blank=True)
    ldap = models.BooleanField(_('Ldap'))
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # manager
    objects = RolesLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'role:{};status_id:{};version:{};valid_from:{};valid_to:{};permissions:{};ldap:{};'. \
            format(self.role, self.status_id, self.version, self.valid_from, self.valid_to, self.permissions, self.ldap)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['role', 'status_id', 'version', 'valid_from', 'valid_to', 'permissions',
                                         'ldap']

    # permissions
    MODEL_ID = '09'
    MODEL_CONTEXT = 'RolesLog'

    class Meta:
        unique_together = None


# manager
class RolesManager(GlobalManager):
    # flags
    LOG_TABLE = RolesLog

    # meta
    GET_MODEL_ORDER = RolesLogManager.GET_MODEL_ORDER
    GET_MODEL_NOT_RENDER = ('permissions',)

    def meta_field(self, data, f_name):
        if f_name == 'ldap':
            data['post'][f_name]['editable'] = False
            data['post'][f_name]['required'] = False

    def find_permission_in_roles(self, roles, permission):
        for role in roles.split(','):
            # query all versions of each role that is in status "productive" or "inactive"
            query = self.filter(role=role).filter(Q(status=Status.objects.productive) |
                                                  Q(status=Status.objects.inactive)).all()
            for obj in query:
                # get the valid role (only one version of all returned versions can be valid!)
                if obj.verify_validity_range:
                    # check each role for the requested permission
                    if any(perm in obj.permissions.split(',') for perm in [permission, settings.ALL_PERMISSIONS]):
                        return True

    def casl(self, roles):
        permissions = list()
        # check all roles of valid user
        for role in roles:
            # get all productive versions of each role
            prod_roles = self.get_by_natural_key_productive(role)
            # catch the valid version
            for valid_prod_role in prod_roles:
                if valid_prod_role.verify_validity_range:
                    # merge permissions of valid role into permission list
                    permissions = list(set(permissions + valid_prod_role.permissions.split(',')))
        casl = list()
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
        return casl

    def permissions(self, roles):
        permissions = []
        # check all roles of valid user
        for role in roles:
            # get all productive versions of each role
            prod_roles = self.get_by_natural_key_productive(role)
            # catch the valid version
            for valid_prod_role in prod_roles:
                if valid_prod_role.verify_validity_range:
                    # merge permissions of valid role into permission list
                    permissions = list(set(permissions + valid_prod_role.permissions.split(',')))
        return permissions


# table
class Roles(GlobalModel):
    # custom fields
    role = models.CharField(_('Role'), max_length=CHAR_DEFAULT, help_text=_('Special characters "{}" are not '
                                                                            'permitted. No whitespaces and numbers.'
                                                                            .format(SPECIALS_REDUCED)),
                            validators=[validate_no_specials_reduced, validate_no_space, validate_no_numbers,
                                        validate_only_ascii])
    permissions = models.CharField(_('Permissions'), help_text='Provide comma separated permission keys.',
                                   max_length=CHAR_BIG, blank=True)
    ldap = models.BooleanField(_('Ldap'))
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'role:{};status_id:{};version:{};valid_from:{};valid_to:{};permissions:{};ldap:{};'. \
            format(self.role, self.status_id, self.version, self.valid_from, self.valid_to, self.permissions, self.ldap)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # manager
    objects = RolesManager()

    # hashing
    HASH_SEQUENCE = ['role', 'status_id', 'version', 'valid_from', 'valid_to', 'permissions', 'ldap']

    # permissions
    MODEL_ID = '03'
    MODEL_CONTEXT = 'Roles'
    perms = {
        '01': 'read',
        '02': 'add',
        '03': 'edit',
        '04': 'delete',
        '05': 'circulation',
        '06': 'reject',
        '07': 'productive',
        '08': 'block',
        '09': 'archive',
        '10': 'inactivate',
        '11': 'version',
        '12': 'version_archived',
        '13': 'ldap'
    }

    # unique field
    UNIQUE = 'role'

    class Meta:
        unique_together = ('lifecycle_id', 'version')
