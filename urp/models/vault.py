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
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.password_validation import password_validators_help_texts

# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, CHAR_MAX


# vault manager
class VaultManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    # meta
    GET_MODEL_EXCLUDE = ('password',
                         'question_one',
                         'question_two',
                         'question_three',
                         'answer_one',
                         'answer_two',
                         'answer_three',)
    GET_MODEL_ORDER = ('username',
                       'initial_password',)
    POST_MODEL_EXCLUDE = ('username',
                          'initial_password',
                          'password',
                          'question_one',
                          'question_two',
                          'question_three',
                          'answer_one',
                          'answer_two',
                          'answer_three',)

    def meta(self, data):
        # add calculated fields for manual password reset
        data['post']['password_new'] = {'verbose_name': 'New password',
                                        'help_text': '{}'.format(password_validators_help_texts()),
                                        'max_length': CHAR_MAX,
                                        'data_type': 'PasswordField',
                                        'required': True,
                                        'unique': False,
                                        'lookup': None,
                                        'editable': True}
        data['post']['password_new_verification'] = {'verbose_name': 'New password verification',
                                                     'help_text': '{}'.format(password_validators_help_texts()),
                                                     'max_length': CHAR_MAX,
                                                     'data_type': 'PasswordField',
                                                     'required': True,
                                                     'unique': False,
                                                     'lookup': None,
                                                     'editable': True}


class Vault(GlobalModel):
    # custom fields
    username = models.CharField(max_length=CHAR_DEFAULT, unique=True)
    initial_password = models.BooleanField()
    password = models.CharField(max_length=CHAR_MAX)
    question_one = models.CharField(max_length=CHAR_MAX, blank=True)
    question_two = models.CharField(max_length=CHAR_MAX, blank=True)
    question_three = models.CharField(max_length=CHAR_MAX, blank=True)
    answer_one = models.CharField(max_length=CHAR_MAX, blank=True)
    answer_two = models.CharField(max_length=CHAR_MAX, blank=True)
    answer_three = models.CharField(max_length=CHAR_MAX, blank=True)

    # manager
    objects = VaultManager()

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['username', 'initial_password', 'password', 'question_one', 'question_two',
                     'question_three', 'answer_one', 'answer_two', 'answer_three']

    # permissions
    MODEL_ID = '17'
    MODEL_CONTEXT = 'passwords'
    perms = {
        '01': 'read',
        # FO-255: changed permission to edit
        '03': 'edit',
    }

    # unique field
    UNIQUE = 'username'

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'username:{};initial_password:{};password:{};question_one:{};question_two:{};' \
                          'question_three:{};answer_one:{};answer_two:{};answer_three:{};' \
            .format(self.username, self.initial_password, self.password, self.question_one, self.question_two,
                    self.question_three, self.answer_one, self.answer_two, self.answer_three)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    def check_password(self, raw_password):
        """
        Return a boolean of whether the raw_password was correct. Handles
        hashing formats behind the scenes.
        """
        def setter(raw_password):
            self.set_password(raw_password)
            # Password hash upgrades shouldn't be considered password changes.
            self._password = None
            self.save(update_fields=["password"])
        return check_password(raw_password, self.password, setter)

    @staticmethod
    def question_answers_fields():
        return {'question_one': 'answer_one',
                'question_two': 'answer_two',
                'question_three': 'answer_three'}

    @property
    def get_questions(self):
        return {'question_one': self.question_one,
                'question_two': self.question_two,
                'question_three': self.question_three}

    @property
    def get_answers(self):
        return {'answer_one': self.answer_one,
                'answer_two': self.answer_two,
                'answer_three': self.answer_three}
