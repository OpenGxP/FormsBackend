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
from django.core.validators import URLValidator
from django.utils.translation import gettext_lazy as _

# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE, FIELD_VERSION, CHAR_MAX, \
    GlobalModelLog
from urp.models.forms.forms import Forms
from basics.models import Status
from urp.validators import validate_no_space, validate_no_specials_reduced, validate_no_numbers, validate_only_ascii, \
    SPECIALS_REDUCED


# log manager
class WebHooksLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('webhook',
                       'url',
                       'form')


# log table
class WebHooksLog(GlobalModelLog):
    # custom fields
    webhook = models.CharField(_('WebHook'), max_length=CHAR_DEFAULT)
    url = models.CharField(_('Url'), max_length=CHAR_MAX, help_text=_('Define target url.'))
    form = models.CharField(_('Form'), max_length=CHAR_DEFAULT, help_text=_('Select form.'))
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT, verbose_name=_('Status'))
    version = FIELD_VERSION

    # manager
    objects = WebHooksLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'webhook:{};url:{};form:{};status_id:{};version:{};valid_from:{};valid_to:{};'. \
            format(self.webhook, self.url, self.form, self.status_id, self.version, self.valid_from, self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['webhook', 'url', 'form', 'status_id', 'version', 'valid_from', 'valid_to']

    # permissions
    MODEL_ID = '51'
    MODEL_CONTEXT = 'WebHooksLog'

    class Meta:
        unique_together = None


# manager
class WebHooksManager(GlobalManager):
    # flags
    LOG_TABLE = WebHooksLog

    # meta
    GET_MODEL_ORDER = WebHooksLogManager.GET_MODEL_ORDER


# table
class WebHooks(GlobalModel):
    # custom fields
    webhook = models.CharField(_('WebHook'), max_length=CHAR_DEFAULT,
                               help_text=_('Special characters "{}" are not permitted. No whitespaces and numbers.'
                                           .format(SPECIALS_REDUCED)),
                               validators=[validate_no_specials_reduced, validate_no_space, validate_no_numbers,
                                           validate_only_ascii])
    url = models.CharField(_('Url'), max_length=CHAR_MAX, help_text=_('Define target url.'),
                           validators=[URLValidator()])
    form = models.CharField(_('Form'), max_length=CHAR_DEFAULT, help_text=_('Select form.'))
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT, verbose_name=_('Status'))
    version = FIELD_VERSION

    # manager
    objects = WebHooksManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'webhook:{};url:{};form:{};status_id:{};version:{};valid_from:{};valid_to:{};'. \
            format(self.webhook, self.url, self.form, self.status_id, self.version, self.valid_from, self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = ['webhook', 'url', 'form', 'status_id', 'version', 'valid_from', 'valid_to']

    # permissions
    MODEL_ID = '50'
    MODEL_CONTEXT = 'WebHooks'

    # unique field
    UNIQUE = 'webhook'

    class Meta:
        unique_together = ('lifecycle_id', 'version')

    # lookup fields
    LOOKUP = {'form': {'model': Forms,
                       'key': 'form',
                       'multi': False,
                       'method': 'select'}}
