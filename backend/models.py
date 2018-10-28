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
import backend.validators as validators


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
    pass


##########
# STATUS #
##########

# manager
class StatusManager(GlobalManager):
    pass


# table
class Status(models.Model):
    # id
    id = FIELD_ID
    # custom fields
    status = models.CharField(_('status'), max_length=CHAR_DEFAULT, unique=True)
    # defaults
    checksum = FIELD_CHECKSUM


###############
# PERMISSIONS #
###############

# manager
class PermissionsManager(GlobalManager):
    pass


# table
class Permissions(models.Model):
    # id
    id = FIELD_ID
    # custom fields
    permission = models.CharField(_('permission'), max_length=CHAR_DEFAULT, unique=True)
    # defaults
    checksum = FIELD_CHECKSUM


#########
# ROLES #
#########

# manager
class RolesManager(GlobalManager):
    pass


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
                    .format(CHAR_DEFAULT, validators.SPECIALS_REDUCED)),
        validators=[validators.validate_no_specials_reduced,
                    validators.validate_no_space],
        unique=True)
    permissions = models.ManyToManyField(Permissions)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION
    checksum = FIELD_CHECKSUM


#########
# USERS #
#########

# manager
class UsersManager(BaseUserManager, GlobalManager):
    def create_superuser(self, username, password):
        user = self.model(username=username,
                          first_name='--',
                          last_name='--',
                          version=1,
                          is_active=True,
                          initial_password=True,
                          checksum='test',
                          last_login=None,
                          email='--',
                          status_id=1)
        user.set_password(password)
        user.save(using=self._db)


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
        validators=[validators.validate_no_specials,
                    validators.validate_no_space])
    last_name = models.CharField(
        _('last name'),
        max_length=CHAR_DEFAULT,
        help_text=_('Required. {} characters or fewer. Special characters "{}" are not permitted. No whitespaces.'
                    .format(CHAR_DEFAULT, string.punctuation)),
        validators=[validators.validate_no_specials,
                    validators.validate_no_space])
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
