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

# app imports
from basics.models import AVAILABLE_STATUS

# python imports
from io import StringIO

# django imports
from django.core.management import call_command
from django.test import TestCase
from django.conf import settings
from django.apps import apps


class InitializeStatus(TestCase):
    def test_OK(self):
        stderr = StringIO()
        stdout = StringIO()
        call_command('initialize-status', stdout=stdout, stderr=stderr)
        for item in AVAILABLE_STATUS:
            self.assertIn('Added status "{}".'.format(item), stdout.getvalue())
        self.assertTrue(stderr.getvalue() == '')


class InitializeSettings(TestCase):
    def test_OK(self):
        stderr = StringIO()
        stdout = StringIO()
        call_command('initialize-settings', stderr=stderr, stdout=stdout)
        for key, value in settings.INITIALIZE_SETTINGS.items():
            self.assertIn('Added setting key: "{}", value: "{}".'
                          .format(key, value), stdout.getvalue())
        self.assertTrue(stderr.getvalue() == '')


class CollectPermissionsTest(TestCase):
    def test_OK(self):
        stderr = StringIO()
        stdout = StringIO()
        call_command('collect-permissions', stdout=stdout, stderr=stderr)
        self.assertIn('Added permission "global.all".', stdout.getvalue())
        models = apps.all_models['urp']
        models.update(apps.all_models['basics'])
        for model in models:
            if models[model].objects.NO_PERMISSIONS:
                continue
            for key, value in models[model].perms.items():
                _model = model
                if model == 'vault':
                    _model = 'passwords'
                self.assertIn('Added permission "{}.{}".'.format(_model, value), stdout.getvalue())
        self.assertTrue(stderr.getvalue() == '')


class CreateRole(TestCase):
    def setUp(self):
        call_command('initialize-status')
        call_command('initialize-settings')

    def test_OK(self):
        stderr = StringIO()
        stdout = StringIO()
        call_command('create-role', name='all', stdout=stdout, stderr=stderr)
        self.assertIn('Role "all" created in status "draft".', stdout.getvalue())
        self.assertIn('Role "all" changed to status "circulation".', stdout.getvalue())
        self.assertIn('Role "all" changed to status "productive".', stdout.getvalue())
        self.assertTrue(stderr.getvalue() == '')

    def test_NOK(self):
        stderr = StringIO()
        stdout = StringIO()
        call_command('create-role', name='all', stdout=stdout)
        self.assertIn('Role "all" created in status "draft".', stdout.getvalue())
        self.assertIn('Role "all" changed to status "circulation".', stdout.getvalue())
        self.assertIn('Role "all" changed to status "productive".', stdout.getvalue())
        new_out = StringIO()
        # FO-131: second call to verify that not a second can be created in status draft
        call_command('create-role', name='all', stdout=new_out, stderr=stderr)
        self.assertTrue(stderr.getvalue() == '')
        self.assertTrue(new_out.getvalue() == '')


class CreateSuperuser(TestCase):
    def setUp(self):
        call_command('initialize-status')
        call_command('initialize-settings')

    def test_OK(self):
        stderr = StringIO()
        stdout = StringIO()
        call_command('create-role', name='all')
        call_command('create-superuser', role='all', username='admin', email='test@opengxp.org',
                     password='FAH2a28djakd2', stdout=stdout, stderr=stderr)
        self.assertIn('User "admin" created.', stdout.getvalue())
        self.assertTrue(stderr.getvalue() == '')

    def test_NOK_no_prod_role(self):
        stderr = StringIO()
        stdout = StringIO()
        call_command('create-superuser', role='all', username='admin', email='test@opengxp.org',
                     password='FAH2a28djakd2', stdout=stdout, stderr=stderr)
        self.assertNotIn('User "admin" created.', stdout.getvalue())
        self.assertIn('Error: Selected role "all" does not exist in status "productive".', stderr.getvalue())

    def test_NOK_exist(self):
        self.test_OK()
        stderr = StringIO()
        stdout = StringIO()
        call_command('create-superuser', role='all', username='admin', email='test@opengxp.org',
                     password='FAH2a28djakd2', stdout=stdout, stderr=stderr)
        self.assertTrue(stdout.getvalue() == '')
        self.assertTrue(stderr.getvalue() == '')
