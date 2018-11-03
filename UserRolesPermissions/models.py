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


# python import
import string


# django imports
from django.db import models
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.utils.translation import gettext_lazy as _


# app imports
from .validators import validate_no_space, validate_no_specials, validate_no_specials_reduced, SPECIALS_REDUCED
from basics.custom import generate_checksum, intersection_two
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, CHAR_MAX, FIELD_VERSION, Status


###############
# PERMISSIONS #
###############

# manager
class PermissionsManager(GlobalManager):
    # hashing
    HASH_SEQUENCE = ['permission']

    # flags
    HAS_VERSION = False
    HAS_STATUS = False


# table
class Permissions(GlobalModel):
    # custom fields
    permission = models.CharField(_('permission'), max_length=CHAR_DEFAULT, unique=True)

    # manager
    objects = PermissionsManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'permission:{};'.format(self.permission)
        return self._verify_checksum(to_hash_payload=to_hash_payload)


#########
# ROLES #
#########

# manager
class RolesManager(GlobalManager):
    # hashing
    HASH_SEQUENCE = ['role', 'status_id', 'version']
    HASH_SEQUENCE_MTM = ['permissions', 'sod_roles']
    MTM_TABLES = {
        'permissions': Permissions,
    }
    SELF_FIELDS = ['sod_roles']


# table
class Roles(GlobalModel):
    # custom fields
    role = models.CharField(
        _('role'),
        max_length=CHAR_DEFAULT,
        help_text=_('Unique and required. {} characters or fewer. Special characters "{}" are not permitted. '
                    'No whitespaces.'
                    .format(CHAR_DEFAULT, SPECIALS_REDUCED)),
        validators=[validate_no_specials_reduced,
                    validate_no_space],
        unique=True)
    permissions = models.ManyToManyField(Permissions)
    sod_roles = models.ManyToManyField('self', blank=True)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # manager
    objects = RolesManager()

    # integrity check
    def verify_checksum(self):
        # get permission objects ordered by id to guarantee correct hashing order
        permissions = self.permissions.order_by('id').all()
        perm_list = list()
        roles = self.sod_roles.order_by('id').all()
        roles_list = list()
        for perm in permissions:
            perm_list.append(perm.id)
        for role in roles:
            roles_list.append(role.id)
        to_hash_payload = 'role:{};status_id:{};version:{};permissions:{};sod_roles:{};'.format(self.role,
                                                                                                self.status_id,
                                                                                                self.version, perm_list,
                                                                                                roles_list)
        return self._verify_checksum(to_hash_payload=to_hash_payload)


#########
# USERS #
#########

# manager
class UsersManager(BaseUserManager, GlobalManager):
    # hashing
    HASH_SEQUENCE = ['username', 'email', 'first_name', 'last_name', 'is_active', 'initial_password', 'password',
                     'status_id', 'version']
    HASH_SEQUENCE_MTM = ['roles']
    MTM_TABLES = {
        'roles': Roles,
    }

    # superuser function for createsuperuser
    def create_superuser(self, username, password):
        fields = {'username': username,
                  'first_name': '--',
                  'last_name': '--',
                  'version': 1,
                  'is_active': True,
                  'initial_password': True,
                  'email': '--',
                  'status_id': 3}  # initial status "Effective" to immediately user superuser
        user = self.model(**fields)
        user.set_password(password)
        fields['password'] = user.password
        user.checksum = 'tbd'
        user.save(using=self._db)

        # build string with row id to generate hash
        fields['roles'] = [Roles.objects.get(pk=1)]  # add initial "all" role
        to_hash = self._generate_to_hash(fields, hash_sequence_mtm=self.HASH_SEQUENCE_MTM, record_id=user.id)
        # get intersection
        intersection = intersection_two(fields.keys(), self.HASH_SEQUENCE_MTM)
        mtm_fields = {k: fields[k] for k in (fields.keys() & intersection)}
        user = self._add_many_to_many(record=user, fields=mtm_fields)
        user.checksum = generate_checksum(to_hash)
        user.save()
        return user


# table
class Users(AbstractBaseUser, GlobalModel):
    # custom fields
    username = models.CharField(_('username'), max_length=CHAR_DEFAULT, unique=True)
    email = models.EmailField(_('email'), max_length=CHAR_MAX)
    first_name = models.CharField(
        _('first name'),
        max_length=CHAR_DEFAULT,
        help_text=_('Required. {} characters or fewer. Special characters "{}" are not permitted. No whitespaces.'
                    .format(CHAR_DEFAULT, string.punctuation)),
        validators=[validate_no_specials,
                    validate_no_space])
    last_name = models.CharField(
        _('last name'),
        max_length=CHAR_DEFAULT,
        help_text=_('Required. {} characters or fewer. Special characters "{}" are not permitted. No whitespaces.'
                    .format(CHAR_DEFAULT, string.punctuation)),
        validators=[validate_no_specials,
                    validate_no_space])
    is_active = models.BooleanField(_('active'))
    initial_password = models.BooleanField(_('initial password'))
    password = models.CharField(_('password'), max_length=CHAR_MAX)
    roles = models.ManyToManyField(Roles)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # manager
    objects = UsersManager()

    # integrity check
    def verify_checksum(self):
        # get permission objects ordered by id to guarantee correct hashing order
        roles = self.roles.order_by('id').all()
        roles_list = list()
        for role in roles:
            roles_list.append(role.id)
        to_hash_payload = 'username:{};email:{};first_name:{};last_name:{};is_active:{};initial_password:{};' \
                          'password:{};status_id:{};version:{};roles:{};'\
            .format(self.username, self.email, self.first_name, self.last_name, self.is_active, self.initial_password,
                    self.password, self.status_id, self.version, roles_list)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    # references
    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []
    last_login = None

    def get_full_name(self):
        return _('{} - {} {}').format(self.username, self.first_name, self.last_name)

    def get_short_name(self):
        return _('{} - {} {}').format(self.username)
