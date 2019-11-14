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

# python import
import string
import itertools

# django imports
from django.db import models
from django.utils import timezone
from django.conf import settings
from django.db.models import Q
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.password_validation import password_validators_help_texts, validate_password

# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE, CHAR_MAX, FIELD_VERSION, \
    Status, CHAR_BIG, GlobalModelLog
from urp.validators import validate_no_space, validate_no_specials, validate_no_numbers, validate_only_ascii
from urp.custom import create_log_record
from basics.custom import generate_checksum, generate_to_hash
from urp.models.vault import Vault
from urp.models.roles import Roles
from urp.models.sod import SoD
from urp.fields import LookupField
from urp.models.profile import Profile


# log manager
class UsersLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_EXCLUDE = ('is_active',)
    GET_MODEL_ORDER = ('username',
                       'first_name',
                       'last_name',
                       'password',
                       'email',
                       'roles',
                       'ldap')
    GET_MODEL_ORDER_NO_PW = ('username',
                             'first_name',
                             'last_name',
                             'email',
                             'roles',
                             'ldap')


# log table
class UsersLog(GlobalModelLog):
    # custom fields
    username = models.CharField(_('Username'), max_length=CHAR_DEFAULT)
    email = models.EmailField(_('Email'), max_length=CHAR_MAX, blank=True)
    first_name = models.CharField(_('First name'), max_length=CHAR_DEFAULT, blank=True)
    last_name = models.CharField(_('Last name'), max_length=CHAR_DEFAULT, blank=True)
    initial_password = models.BooleanField(_('Initial password'))
    ldap = models.BooleanField(_('Ldap'))
    roles = models.CharField(_('Roles'), max_length=CHAR_BIG)
    is_active = models.BooleanField(_('Is_active'))
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # manager
    objects = UsersLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'username:{};email:{};first_name:{};last_name:{};is_active:{};initial_password:{};' \
                          'status_id:{};version:{};valid_from:{};valid_to:{};ldap:{};roles:{};' \
            .format(self.username, self.email, self.first_name, self.last_name, self.is_active, self.initial_password,
                    self.status_id, self.version, self.valid_from, self.valid_to, self.ldap, self.roles)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['username', 'email', 'first_name', 'last_name', 'is_active',
                                         'initial_password', 'status_id', 'version', 'valid_from', 'valid_to', 'ldap',
                                         'roles']

    # permissions
    MODEL_ID = '10'
    MODEL_CONTEXT = 'UsersLog'

    class Meta:
        unique_together = None


# manager
class UsersManager(BaseUserManager, GlobalManager):
    # flags
    LOG_TABLE = UsersLog

    # meta
    GET_MODEL_EXCLUDE = ('is_active', 'password')
    GET_MODEL_ORDER = UsersLogManager.GET_MODEL_ORDER
    GET_MODEL_ORDER_NO_PW = UsersLogManager.GET_MODEL_ORDER_NO_PW
    POST_MODEL_EXCLUDE = ('initial_password', 'is_active')

    @property
    def existing_users(self):
        return self.all().values_list('username', flat=True)

    def exist(self, username):
        return self.filter(username=username).exists()

    def get_valid_user_by_email(self, email):
        query = self.filter(email=email).all()
        if not query:
            return
        for record in query:
            if record.verify_validity_range:
                return record
        return

    # superuser function for createsuperuser
    def create_superuser(self, username, password, role, email, initial_password=True):
        # initial status "Effective" to immediately user superuser
        now = timezone.now()
        status_id = Status.objects.productive
        fields = {'username': username,
                  'first_name': username,
                  'last_name': username,
                  'version': 1,
                  'is_active': True,
                  'valid_from': now,
                  'email': email,
                  'status_id': status_id,
                  'ldap': False,
                  'roles': [role]}
        user = self.model(**fields)
        # set random password for user object because required
        user.set_password(self.make_random_password())
        vault_fields = {
            'username': username,
            'initial_password': initial_password
        }
        vault = Vault(**vault_fields)
        vault.set_password(password)
        vault_fields['password'] = vault.password

        # build string with row id to generate hash for user
        to_hash = generate_to_hash(fields, hash_sequence=user.HASH_SEQUENCE, unique_id=user.id,
                                   lifecycle_id=user.lifecycle_id)
        user.checksum = generate_checksum(to_hash)

        # build string with row id to generate hash for vault
        to_hash = generate_to_hash(vault_fields, hash_sequence=vault.HASH_SEQUENCE, unique_id=vault.id)
        vault.checksum = generate_checksum(to_hash)
        try:
            user.full_clean()
            vault.full_clean()
        except ValidationError as e:
            raise e
        else:
            user.save()
            vault.save()
        # log record
        context = dict()
        context['function'] = 'init'
        fields['initial_password'] = initial_password
        create_log_record(model=self.model, context=context, obj=user, signature=False,
                          validated_data=fields, action=settings.DEFAULT_LOG_CREATE)

        # create profile
        Profile.objects.generate_profile(username=username)

        return user


# table
class Users(AbstractBaseUser, GlobalModel):
    # custom fields
    username = models.CharField(
        _('Username'),
        help_text=_('Special characters "{}" are not permitted. No whitespaces and numbers.'
                    .format(string.punctuation)),
        max_length=CHAR_DEFAULT,
        validators=[validate_no_specials,
                    validate_no_space,
                    validate_no_numbers,
                    validate_only_ascii])
    email = models.EmailField(
        _('Email'),
        help_text='Email must be provided in format example@example.com.',
        max_length=CHAR_MAX)
    first_name = models.CharField(
        _('First name'),
        max_length=CHAR_DEFAULT,
        help_text=_('Special characters "{}" are not permitted. No whitespaces and numbers.'
                    .format(string.punctuation)),
        validators=[validate_no_specials,
                    validate_no_space,
                    validate_no_numbers,
                    validate_only_ascii],
        blank=True)
    last_name = models.CharField(
        _('Last name'),
        max_length=CHAR_DEFAULT,
        help_text=_('Special characters "{}" are not permitted. No whitespaces and numbers.'
                    .format(string.punctuation)),
        validators=[validate_no_specials,
                    validate_no_space,
                    validate_no_numbers,
                    validate_only_ascii],
        blank=True)
    ldap = models.BooleanField(
        _('LDAP'),
        help_text=_('Specify if user is manually or LDAP manged.'))
    roles = LookupField(
        _('Roles'),
        help_text='Select role(s).',
        max_length=CHAR_BIG)
    password = models.CharField(
        _('Password'),
        help_text='{}'.format(password_validators_help_texts()),
        max_length=CHAR_MAX,
        validators=[validate_password])
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # manager
    objects = UsersManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'username:{};email:{};first_name:{};last_name:{};is_active:{};' \
                          'status_id:{};version:{};valid_from:{};valid_to:{};ldap:{};roles:{};'\
            .format(self.username, self.email, self.first_name, self.last_name, self.is_active,
                    self.status_id, self.version, self.valid_from, self.valid_to, self.ldap, self.roles)
        user = self._verify_checksum(to_hash_payload=to_hash_payload)
        if not self.ldap:
            vault = Vault.objects.filter(username=self.username).get()
            user_ext = vault.verify_checksum()
            if user and user_ext:
                return True
        else:
            return user

    @property
    def get_status(self):
        return self.status.status

    def permission(self, value):
        return Roles.objects.find_permission_in_roles(roles=self.roles, permission=value)

    # FO-123: new check to verify is any assigned role is productive and valid
    @property
    def verify_valid_roles(self):
        # determine assigned roles by splitting string
        assigned_roles = self.roles.split(',')
        # parse roles
        for assigned_role in assigned_roles:
            # try to get productive versions of each role
            try:
                productive_roles = Roles.objects.get_by_natural_key_productive(assigned_role)
            # in case no productive roles, do nothing
            except Roles.DoesNotExist:
                pass
            # if productive role exists, parse if any of them is valid
            else:
                for role in productive_roles:
                    if role.verify_validity_range:
                        return True
        # if no assigned roles is prod and valid, return none

    def has_role(self, role):
        if role in self.roles.split(','):
            return True

    @property
    def verify_sod(self):
        # determine pairs of assigned roles
        combinations = itertools.combinations(self.roles.split(','), 2)
        status_effective_id = Status.objects.productive
        # parse combinations
        for a, b in combinations:
            # look for productive sod records
            query = SoD.objects.filter(Q(base=a, conflict=b, status__id=status_effective_id) |
                                       Q(base=b, conflict=a, status__id=status_effective_id)).all()
            # check if records are valid
            for record in query:
                if record.verify_validity_range:
                    return False
        return True

    # references
    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'username'
    last_login = None
    is_active = models.BooleanField(_('is_active'))

    # unique field
    UNIQUE = 'username'

    class Meta:
        unique_together = ('lifecycle_id', 'version')

    # hashing
    HASH_SEQUENCE = ['username', 'email', 'first_name', 'last_name', 'is_active',
                     'status_id', 'version', 'valid_from', 'valid_to', 'ldap', 'roles']

    # permissions
    MODEL_ID = '04'
    MODEL_CONTEXT = 'Users'

    def get_full_name(self):
        if self.first_name == '' and self.last_name == '':
            return self.username
        return _('{} {} ({})').format(self.first_name, self.last_name, self.username)

    def get_short_name(self):
        return _('{} - {} {}').format(self.username)

    def check_password(self, raw_password):
        """
        direct password check to vault
        """
        user = Vault.objects.filter(username=self.username).get()
        return user.check_password(raw_password)

    @property
    def initial_password(self):
        if not self.ldap:
            user = Vault.objects.filter(username=self.username).get()
            return user.initial_password
        else:
            return False

    # lookup fields
    LOOKUP = {'roles': {'model': Roles,
                        'key': 'role',
                        'multi': True,
                        'method': 'select'}}
