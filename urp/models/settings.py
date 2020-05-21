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


# django imports
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

# app imports
from basics.custom import generate_checksum, generate_to_hash
from basics.models import GlobalModel, GlobalModelLog, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE
from urp.models.roles import Roles

# log manager
class SettingsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('key',
                       'default',
                       'value',)


# log table
class SettingsLog(GlobalModelLog):
    # custom fields
    key = models.CharField(_('Key'), max_length=CHAR_DEFAULT)
    default = models.CharField(_('Default'), max_length=CHAR_DEFAULT)
    value = models.CharField(_('Value'), max_length=CHAR_DEFAULT)

    # manager
    objects = SettingsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'key:{};default:{};value:{};'.format(self.key, self.default, self.value)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['key', 'default', 'value']

    # permissions
    MODEL_ID = '14'
    MODEL_CONTEXT = 'SettingsLog'


# manager
class SettingsManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    LOG_TABLE = SettingsLog

    # meta
    GET_MODEL_ORDER = SettingsLogManager.GET_MODEL_ORDER

    def meta_field(self, data, f_name):
        # settings non-editable field for better visualisation
        if f_name == 'key':
            data['post'][f_name]['editable'] = False
            data['post'][f_name]['required'] = False
        if f_name == 'default':
            data['post'][f_name]['editable'] = False
            data['post'][f_name]['required'] = False

    # FO-260: add misc lookup data for signature and comment selection
    def meta(self, data):
        # signature
        data['data']['signature'] = {'data': self.model.ALLOWED_SIGNATURE,  # static select
                                     'multi': False,
                                     'method': 'select'}
        # comment
        data['data']['comment'] = {'data': self.model.ALLOWED_COMMENT,  # static select
                                   'multi': False,
                                   'method': 'select'}

        # timezones
        data['data']['profile.default.timezone'] = {'data': settings.SETTINGS_TIMEZONES,
                                                    'multi': False,
                                                    'method': 'select'}

        # timezones
        _data = [self.core_devalue] + list(Roles.objects.get_by_natural_key_productive_list(key='role'))
        data['data']['core.initial_role'] = {'data': _data,
                                             'multi': False,
                                             'method': 'select'}
        # add calculated field "lookup"
        data['get']['lookup'] = {'verbose_name': 'Lookup',
                                 'data_type': 'CharField',
                                 'render': False}

    # FO-277: method to define initial role in settings
    def define_initial_role(self, role):
        data = {'key': 'core.initial_role',
                'default': role,
                'value': role}
        obj = self.filter(key='core.initial_role').get()
        obj.default = role
        obj.value = role

        to_hash = generate_to_hash(fields=data, hash_sequence=self.model.HASH_SEQUENCE, unique_id=obj.id)
        obj.checksum = generate_checksum(to_hash)
        obj.full_clean()
        obj.save()

    @property
    def auth_maxloginattempts(self):
        try:
            return int(self.filter(key='auth.max_login_attempts').get().value)
        except self.model.DoesNotExist:
            return settings.MAX_LOGIN_ATTEMPTS

    @property
    def core_devalue(self):
        try:
            return self.filter(key='core.devalue').get().value
        except self.model.DoesNotExist:
            return settings.DEFAULT_SYSTEM_DEVALUE

    @property
    def core_system_username(self):
        try:
            return self.filter(key='core.system_username').get().value
        except self.model.DoesNotExist:
            return settings.DEFAULT_SYSTEM_USER

    @property
    def core_timestamp_format(self):
        try:
            return self.filter(key='core.timestamp_format').get().value
        except self.model.DoesNotExist:
            return settings.DEFAULT_FRONT_TIMESTAMP

    @property
    def core_auto_logout(self):
        try:
            return int(self.filter(key='core.auto_logout').get().value)
        except self.model.DoesNotExist:
            return settings.DEFAULT_AUTO_LOGOUT

    @property
    def core_password_reset_time(self):
        try:
            return int(self.filter(key='core.password_reset_time').get().value)
        except self.model.DoesNotExist:
            return settings.DEFAULT_PASSWORD_RESET_TIME

    @property
    def email_sender(self):
        try:
            return self.filter(key='email.sender').get().value
        except self.model.DoesNotExist:
            return settings.DEFAULT_EMAIL_SENDER

    @property
    def core_initial_role(self):
        try:
            return self.filter(key='core.initial_role').get().value
        except self.model.DoesNotExist:
            return settings.DEFAULT_INITIAL_ROLE

    def dialog_signature(self, dialog, perm):
        if self.filter(key='dialog.{}.signature.{}'.format(dialog, perm)).get().value == 'signature':
            return True
        return

    def dialog_signature_dict(self, dialog):
        query = self.filter(key__contains='dialog.{}.signature.'.format(dialog)).values('key', 'value').all()
        for x in query:
            x['key'] = x['key'].split('.')[3]
        return query

    def dialog_comment(self, dialog, perm):
        try:
            return self.filter(key='dialog.{}.comment.{}'.format(dialog, perm)).get().value
        except self.model.DoesNotExist:
            return settings.DEFAULT_DIALOG_COMMENT

    def dialog_comment_dict(self, dialog):
        query = self.filter(key__contains='dialog.{}.comment.'.format(dialog)).values('key', 'value').all()
        for x in query:
            x['key'] = x['key'].split('.')[3]
        return query

    @property
    def profile_default_timezone(self):
        try:
            return self.filter(key='profile.default.timezone').get().value
        except self.model.DoesNotExist:
            return settings.PROFILE_DEFAULT_TIMEZONE

    @property
    def rtd_number_range(self):
        try:
            return int(self.filter(key='rtd.number_range').get().value)
        except self.model.DoesNotExist:
            return settings.DEFAULT_RT_NUMBER_RANGE


# table
class Settings(GlobalModel):
    # custom fields
    key = models.CharField(_('Key'), max_length=CHAR_DEFAULT, unique=True)
    default = models.CharField(_('Default'), max_length=CHAR_DEFAULT)
    value = models.CharField(_('Value'), max_length=CHAR_DEFAULT)

    # manager
    objects = SettingsManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'key:{};default:{};value:{};'.format(self.key, self.default, self.value)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['key', 'default', 'value']

    # permissions
    MODEL_ID = '13'
    MODEL_CONTEXT = 'Settings'
    perms = {
        '01': 'read',
        '03': 'edit',
    }

    UNIQUE = 'key'

    ALLOWED_SIGNATURE = ['logging', 'signature']
    ALLOWED_COMMENT = ['none', 'optional', 'mandatory']

    @property
    def lookup(self):
        if 'signature' in self.key:
            return 'signature'
        elif 'comment' in self.key:
            return 'comment'
        else:
            return self.key
