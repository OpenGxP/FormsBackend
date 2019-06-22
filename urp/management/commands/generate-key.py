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
from django.core.management.base import BaseCommand
from django.conf import settings


CRYPTO_KEY = settings.SECURITY_DIR + '/keys/' + settings.CRYPTO_KEY


class Command(BaseCommand):
    help = 'Generate AES key.'

    def handle(self, *args, **options):
        # generate key
        key = Fernet.generate_key()

        # save key to file
        with open(CRYPTO_KEY, 'wb') as file:
            file.write(key)

        self.stdout.write(self.style.SUCCESS('Successfully generated crypto key.'))
