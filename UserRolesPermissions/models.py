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
from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.utils.translation import gettext_lazy as _


# app imports
from .validators import validate_no_space, validate_no_specials, validate_no_specials_reduced, SPECIALS_REDUCED
from .custom import generate_checksum, HASH_ALGORITHM, generate_to_hash


##########
# GLOBAL #
##########

# char lengths
CHAR_DEFAULT = 100
CHAR_MAX = 255

# default fields
FIELD_ID = models.AutoField(primary_key=True)
FIELD_VERSION = models.PositiveIntegerField()
FIELD_CHECKSUM = models.CharField(_('checksum'), max_length=CHAR_MAX)


class GlobalManager(models.Manager):
    def generate_to_hash(self, fields, record_id=None):
        """Generic function to build hash string for record fields.

        :param fields: dictionary containing all mandatory fields and values
        :type fields: dict

        :param record_id: id of the record to hash, default is no id
        :type record_id: int / AutoField

        :return: string to hash
        :rtype: str
        """
        return generate_to_hash(fields=fields, hash_sequence=self.HASH_SEQUENCE, record_id=record_id)

    def verify_checksum(self, update, record_id=None):
        """Generic function to verify checksum without id.

        :param update: django queryset
        :type update: dict

        :param record_id: id of the record to verify, default is no id
        :type record_id: int

        :return: success flag
        :rtype: bool
        """
        if record_id:
            to_hash = 'id:{};'.format(record_id)
        else:
            to_hash = str()
        for field in self.HASH_SEQUENCE:
            to_hash += '{}:{};'.format(field, update[field])
        to_hash += settings.SECRET_HASH_KEY
        return HASH_ALGORITHM.verify(to_hash, update['checksum'])

    def new(self, **fields):
        """Generic function to create new records, including hashing. "id" is always fist, "checksum" always last.

            :param fields: dictionary containing all mandatory fields and values
            :type fields: dict

            :return: success flag
            :rtype: bool
        """
        # hash values without id
        to_hash = self.generate_to_hash(fields)
        fields['checksum'] = generate_checksum(to_hash)
        record = self.create(**fields)

        # get values of new created record with id
        update = self.filter(id=record.id).values()[0]

        # build string with row id to generate hash
        to_hash = self.generate_to_hash(fields, record_id=record.id)

        # verify hash without id
        if self.verify_checksum(update):
            # generate hash and update field checksum
            record.checksum = generate_checksum(to_hash)
            record.save()
        else:
            raise NameError('Record with id={} manipulated'.format(record.id))


##########
# STATUS #
##########

# manager
class StatusManager(GlobalManager):
    # hashing
    HASH_SEQUENCE = ['status']


# table
class Status(models.Model):
    # id
    id = FIELD_ID
    # custom fields
    status = models.CharField(_('status'), max_length=CHAR_DEFAULT, unique=True)
    # defaults
    checksum = FIELD_CHECKSUM

    # manager
    objects = StatusManager()


###############
# PERMISSIONS #
###############

# manager
class PermissionsManager(GlobalManager):
    # hashing
    HASH_SEQUENCE = ['permission']


# table
class Permissions(models.Model):
    # id
    id = FIELD_ID
    # custom fields
    permission = models.CharField(_('permission'), max_length=CHAR_DEFAULT, unique=True)
    # defaults
    checksum = FIELD_CHECKSUM

    # manager
    objects = PermissionsManager()


#########
# ROLES #
#########

# manager
class RolesManager(GlobalManager):
    # hashing
    HASH_SEQUENCE = ['role', 'permissions', 'status', 'version']


# table
class Roles(models.Model):
    # id
    id = FIELD_ID
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
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION
    checksum = FIELD_CHECKSUM

    # manager
    objects = RolesManager()


#########
# USERS #
#########

# manager
class UsersManager(BaseUserManager, GlobalManager):
    # hashing
    HASH_SEQUENCE = ['username', 'email', 'first_name', 'last_name', 'is_active', 'initial_password', 'password',
                     'status_id', 'version']

    def create_superuser(self, username, password):
        fields = {'username': username,
                  'first_name': '--',
                  'last_name': '--',
                  'version': 1,
                  'is_active': True,
                  'initial_password': True,
                  'last_login': None,
                  'email': '--',
                  'status_id': 3}
        user = self.model(**fields)
        user.set_password(password)
        fields['password'] = user.password
        to_hash = self.generate_to_hash(fields)
        user.checksum = generate_checksum(to_hash)
        user.save(using=self._db)

        # get values of new created record with id
        update = self.filter(id=user.id).values()[0]

        # build string with row id to generate hash
        to_hash = self.generate_to_hash(fields, record_id=user.id)

        # verify hash without id
        if self.verify_checksum(update):
            # generate hash and update field checksum
            user.checksum = generate_checksum(to_hash)
            user.save()
        else:
            raise NameError('Record with id={} manipulated'.format(user.id))


# table
class Users(AbstractBaseUser):
    # id
    id = FIELD_ID
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
    checksum = FIELD_CHECKSUM

    # manager
    objects = UsersManager()

    # references
    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    def get_full_name(self):
        return _('{} - {} {}').format(self.username, self.first_name, self.last_name)

    def get_short_name(self):
        return _('{} - {} {}').format(self.username)
