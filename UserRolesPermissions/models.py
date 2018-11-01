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
from .custom import generate_checksum, generate_to_hash, HASH_ALGORITHM


##########
# GLOBAL #
##########

# char lengths
CHAR_DEFAULT = 100
CHAR_MAX = 255

# default fields
FIELD_VERSION = models.PositiveIntegerField()


class GlobalManager(models.Manager):
    # hashing
    HASH_SEQUENCE_MTM = None

    # flags
    HAS_VERSION = True
    HAS_STATUS = True

    def _generate_to_hash(self, fields, hash_sequence_mtm=None, record_id=None):
        """Generic function to build hash string for record fields.

        :param fields: dictionary containing all mandatory fields and values
        :type fields: dict

        :param hash_sequence_mtm: list of many to many fields in correct hash order, default is None
        :type hash_sequence_mtm: list

        :param record_id: id of the record to hash, default is no id
        :type record_id: int / AutoField

        :return: string to hash
        :rtype: str
        """
        return generate_to_hash(fields=fields, hash_sequence=self.HASH_SEQUENCE, hash_sequence_mtm=hash_sequence_mtm,
                                record_id=record_id)

    def create(self, **fields):
        """Generic function to create new records, including hashing. "id" is always fist, "checksum" always last.

            :param fields: dictionary containing all mandatory fields and values excluding "id", "version", "status"
            and "checksum", many to many fields must be passed via a list containing integers on the pk/id of the
            related record
            :type fields: dict

            :return: success flag
            :rtype: bool
        """
        # verify that many to many fields are
        if self.HASH_SEQUENCE_MTM:
            for mtm_field in self.HASH_SEQUENCE_MTM:
                if not isinstance(fields[mtm_field], list):
                    raise TypeError('Many to many fields expect lists with integers.')
                for field in fields[mtm_field]:
                    if not isinstance(field, int):
                        raise TypeError('Many to many fields expect lists with integers.')
        # new records that have versions always start with version = 1
        if self.HAS_VERSION:
            fields['version'] = 1
        # new records that have status always start with status = 1 (Draft)
        if self.HAS_STATUS:
            fields['status_id'] = 1
        # save to db to get ID, checksum field is set to "tbd"
        # "tbd" is no valid hash string and therefore always return False on check
        fields['checksum'] = 'tbd'
        # reduce fields by many to many fields, they are added later
        tmp_fields = dict(fields)
        if self.HASH_SEQUENCE_MTM:
            for field in self.HASH_SEQUENCE_MTM:
                tmp_fields.pop(field)
        record = self.create(**tmp_fields)
        # build string with row id to generate complete hash string
        if self.HASH_SEQUENCE_MTM:
            to_hash = self._generate_to_hash(fields, hash_sequence_mtm=self.HASH_SEQUENCE_MTM, record_id=record.id)
        else:
            to_hash = self._generate_to_hash(fields, record_id=record.id)
        # if many to many table, add records
        if self.HASH_SEQUENCE_MTM:
            # TABLE INDIVIDUAL FUNCTION TO CALL, CUSTOMIZED PER TABLE
            record = self._add_many_to_many(record=record, fields=fields)
        # save valid checksum to record, including id
        record.checksum = generate_checksum(to_hash)
        record.save()
        return record


class GlobalModel(models.Model):
    # id
    id = models.AutoField(primary_key=True)
    checksum = models.CharField(_('checksum'), max_length=CHAR_MAX)

    class Meta:
        abstract = True

    def _verify_checksum(self, to_hash_payload):
        to_hash = 'id:{};'.format(self.id)
        to_hash += to_hash_payload
        to_hash += settings.SECRET_HASH_KEY
        try:
            return HASH_ALGORITHM.verify(to_hash, self.checksum)
        except ValueError:
            return False


##########
# STATUS #
##########

# manager
class StatusManager(GlobalManager):
    # hashing
    HASH_SEQUENCE = ['status']

    # flags
    HAS_VERSION = False
    HAS_STATUS = False


# table
class Status(GlobalModel):
    # custom fields
    status = models.CharField(_('status'), max_length=CHAR_DEFAULT, unique=True)

    # manager
    objects = StatusManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'status:{};'.format(self.status)
        return self._verify_checksum(to_hash_payload=to_hash_payload)


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
    HASH_SEQUENCE_MTM = ['permissions']

    # many to many function
    @staticmethod
    def _add_many_to_many(record, fields):
        for pk in fields['permissions']:
            perm = Permissions.objects.get(pk=pk)
            record.permissions.add(perm)
        return record


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
        for perm in permissions:
            perm_list.append(perm.id)
        to_hash_payload = 'role:{};status_id:{};version:{};permissions:{};'.format(self.role, self.status_id,
                                                                                   self.version, perm_list)
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

    # many to many function
    @staticmethod
    def _add_many_to_many(record, fields):
        for pk in fields['roles']:
            role = Roles.objects.get(pk=pk)
            record.roles.add(role)
        return record

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
        fields['roles'] = [1]  # add initial "all" role
        to_hash = self._generate_to_hash(fields, hash_sequence_mtm=self.HASH_SEQUENCE_MTM, record_id=user.id)
        user = self._add_many_to_many(record=user, fields=fields)
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
