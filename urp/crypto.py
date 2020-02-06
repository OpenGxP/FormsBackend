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

# crypto imports
from cryptography.fernet import Fernet

# django imports
from django.conf import settings


def encrypt(value):
    # encode to bytes
    encoded = value.encode()
    f = Fernet(settings.CRYPTO_KEY)
    encrypted = f.encrypt(encoded)

    # decode to string for storing in db
    decoded = encrypted.decode('utf-8')

    # return string
    return decoded


def decrypt(value):
    # encode to bytes before decryption
    encoded = value.encode()

    f = Fernet(settings.CRYPTO_KEY)
    decrypted = f.decrypt(encoded)

    # decode to string
    decoded = decrypted.decode('utf-8')

    # return string
    return decoded
