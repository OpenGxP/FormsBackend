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


# python imports
import os
import base64
from passlib.hash import sha512_crypt
from jinja2 import Template

# django imports
from django.conf import settings
from django.apps import apps
from django.core.exceptions import ValidationError, ImproperlyConfigured
from django.core.mail import send_mail

# crypto imports
from Crypto.Cipher import AES


##########
# GLOBAL #
##########

HASH_ALGORITHM = sha512_crypt


###########
# HASHING #
###########

def generate_checksum(to_hash):
    """
    Generates a hash string.
    """
    return HASH_ALGORITHM.using(rounds=1000).hash(to_hash)


def generate_to_hash(fields, hash_sequence, unique_id, lifecycle_id=None):
    """
    Generic function to build hash string for record fields.
    """
    to_hash = 'id:{};'.format(unique_id)
    if lifecycle_id:
        to_hash += 'lifecycle_id:{};'.format(lifecycle_id)
    # add static fields
    for attr in hash_sequence:
        try:
            to_hash += '{}:{};'.format(attr, fields[attr])
        except KeyError:
            if attr == 'valid_to' or attr == 'valid_from':
                to_hash += '{}:None;'.format(attr)
            else:
                to_hash += '{}:;'.format(attr)
    # some pepper for the soup
    to_hash += settings.SECRET_HASH_KEY
    return to_hash


def intersection_two(list_one, list_two):
    return list(set(list_one) & set(list_two))


def get_model_by_string(model_str):
    models = apps.all_models['urp']
    models.update(apps.all_models['basics'])
    for model in models:
        if models[model].MODEL_CONTEXT:
            if models[model].MODEL_CONTEXT.lower() == model_str.lower():
                return models[model]
    raise ValidationError('Requested model "{}" does not exist.'.format(model_str))


def value_to_int(value):
    """Converts value to real integer

    :param value: string with integer content or integer
    :type value: str/int
    :return: int
    """
    if not isinstance(value, str):
        if isinstance(value, int):
            return value
        else:
            raise TypeError('Argument of type string or integer expected.')
    try:
        return int(value)
    except ValueError:
        raise ValueError('Can not convert "{}" to integer.'.format(value))


def value_to_bool(value):
    """Converts 0/1 values to bool

    :param value: value containing 0 or 1
    :type value: int/str
    :return: bool
    """
    if not isinstance(value, int):
        value = value_to_int(value)
    if value > 1:
        raise ValueError('Only 0 or 1 allowed.')
    return bool(value)


# function for required settings from environment variable
def require_env(env):
    """Raise an error if environment variable is not defined.

    :param env: environment variable
    :type env: str
    :return: returns string or integer of env variable
    :rtype: str/int
    """
    if not isinstance(env, str):
        raise TypeError('Argument of type string expected.')
    raw_value = os.getenv(env)
    if raw_value is None:
        raise ImproperlyConfigured('Required environment variable "{}" is not set.'.format(env))
    try:
        return value_to_int(raw_value)
    except ValueError:
        return raw_value


# function for required settings from local files
def require_file(path, file_name):
    """Raise an error if file for configuration not existing or empty.

        :param path: absolute path to file ending with /
        :type path: str
        :param file_name: file name
        :type file_name: str
        :return: returns string of file content
        :rtype: str
    """
    if not isinstance(path, str) or not isinstance(file_name, str):
        raise TypeError('Argument of type string expected.')
    try:
        with open(path + file_name) as local_file:
            content = local_file.read().strip()
            if content:
                return content
            else:
                raise ImproperlyConfigured('File "{}" is empty.'.format(file_name))
    except FileNotFoundError:
        raise


def encrypt(value):
    cipher = AES.new(settings.CRYPT_KEY, AES.MODE_CFB, settings.IV)
    _crypt = cipher.encrypt(value)
    return str(base64.b64encode(_crypt), 'utf-8')


def decrypt(value):
    cipher = AES.new(settings.CRYPT_KEY, AES.MODE_CFB, settings.IV)
    _crypt = base64.b64decode(value)
    return cipher.decrypt(_crypt).decode('utf-8')


def unique_items(compare_list):
    """Method compares all items of a list to check if they are all unique.

    :param compare_list: list of items that shall be checked if all items are unique
    :type compare_list: list
    :return: true / false
    :rtype: bool
    """
    length = len(compare_list)
    for x in range(length):
        for y in range(length):
            if y == length or y == x:
                continue
            if compare_list[x] == compare_list[y]:
                return False
    return True


def render_email_from_template(template_file_name, data=None):
    # try to get custom template, if not applicable, use default template
    try:
        template = require_file(path=settings.EMAIL_DIR + '/custom/', file_name=template_file_name)
    except FileNotFoundError:
        template = require_file(path=settings.EMAIL_DIR + '/default/', file_name=template_file_name)
    t = Template(template)
    if data:
        return t.render(**data)
    return t.render()


def send_email(email, html_message, subject):
    def send():
        return send_mail(subject=subject,
                         message='opengxp message',
                         html_message=html_message,
                         from_email='from@example.com',
                         recipient_list=[email],
                         fail_silently=True)

    for x in range(2):
        result = send()
        if result == 1:
            break
