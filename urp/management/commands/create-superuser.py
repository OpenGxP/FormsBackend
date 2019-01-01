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
import sys
import getpass

# app imports
from basics.models import Status
from urp.models import Roles

# django imports
from django.contrib.auth import get_user_model
from django.core import exceptions
from django.db.models import Q
from django.core.management.base import BaseCommand
from django.contrib.auth.password_validation import validate_password


class NotRunningInTTYException(Exception):
    pass


class Command(BaseCommand):
    help = 'Create a user directly in status "productive".'
    stealth_options = ('stdin',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.UserModel = get_user_model()
        self.username_field = self.UserModel._meta.get_field(self.UserModel.USERNAME_FIELD)
        self.role_field = self.UserModel._meta.get_field('roles')

    def add_arguments(self, parser):
        super(Command, self).add_arguments(parser)
        parser.add_argument('--username', dest='user', help='Specify the user name.', default=None)
        parser.add_argument('--password', dest='pw', help='Define a password.', default=None)
        parser.add_argument('--role', dest='role', help='Name the user role.', default=None)

    def execute(self, *args, **options):
        self.stdin = options.get('stdin', sys.stdin)  # Used for testing
        return super().execute(*args, **options)

    def handle(self, *args, **options):
        user_data = {}
        fake_user_data = {}
        username = options.get('user')
        if not username:
            self.stderr.write("Error: Username is mandatory.")
        else:
            username = self.clean_input(self.username_field, username)

        # role
        role = options.get('role')
        if not role:
            self.stderr.write("Error: Role is mandatory.")
        else:
            role = self.clean_input(self.role_field, role)
            if role:
                # verify if selected role exists and is in status "productive"
                try:
                    Roles.objects.get(role=role, status=Status.objects.productive)
                except Roles.DoesNotExist:
                    self.stderr.write('Error: Selected role "{}" does not exist in status "productive".'.format(role))
                    role = None

        # password
        password = options.get('pw')
        if not password:
            try:
                if hasattr(self.stdin, 'isatty') and not self.stdin.isatty():
                    raise NotRunningInTTYException("Not running in a TTY")

                while password is None:
                    password = getpass.getpass()
                    password2 = getpass.getpass('Password (again): ')
                    if password != password2:
                        self.stderr.write("Error: Your passwords didn't match.")
                        password = None
                        # Don't validate passwords that don't match.
                        continue
                    if password.strip() == '':
                        self.stderr.write("Error: Blank passwords aren't allowed.")
                        password = None
                        # Don't validate blank passwords.
                        continue
                    try:
                        validate_password(password2, self.UserModel(**fake_user_data))
                    except exceptions.ValidationError as err:
                        self.stderr.write('\n'.join(err.messages))
                        password = None
                        continue
            except KeyboardInterrupt:
                self.stderr.write('Operation cancelled.')
                sys.exit(1)
        else:
            if password.strip() == '':
                self.stderr.write("Error: Blank passwords aren't allowed.")
            try:
                validate_password(password, self.UserModel(**fake_user_data))
            except exceptions.ValidationError as err:
                self.stderr.write('\n'.join(err.messages))

        if username and password and role:
            user_data[self.UserModel.USERNAME_FIELD] = username
            user_data['password'] = password
            user_data['role'] = role

            try:
                user = {self.UserModel.USERNAME_FIELD: username}
                self.UserModel.objects.filter(**user).filter(Q(status=Status.objects.circulation) |
                                                             Q(status=Status.objects.productive)).get()
                self.stderr.write('Error: User "{}" already exists.'.format(username))
            except self.UserModel.DoesNotExist:
                user = self.UserModel.objects.create_superuser(**user_data)
                if user:
                    self.stdout.write(self.style.SUCCESS('Superuser "{}" created successfully.'.format(username)))

    def clean_input(self, field, value):
        """
        Clean input for model field.
        """
        try:
            val = field.clean(value, None)
        except exceptions.ValidationError as e:
            self.stderr.write("Error: %s" % '; '.join(e.messages))
            val = None
        return val
