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
from io import StringIO

# django imports
from django.core.management import call_command
from django.test import TestCase


class InitializeStatus(TestCase):
    def test_OK(self):
        out = StringIO()
        call_command('initialize-status', stdout=out)
        self.assertIn('Successfully added status "draft".', out.getvalue())
        self.assertIn('Successfully added status "circulation".', out.getvalue())
        self.assertIn('Successfully added status "productive".', out.getvalue())
        self.assertIn('Successfully added status "blocked".', out.getvalue())
        self.assertIn('Successfully added status "inactive".', out.getvalue())
        self.assertIn('Successfully added status "archived".', out.getvalue())


class CollectPermissionsTest(TestCase):
    def test_OK(self):
        out = StringIO()
        call_command('collect-permissions', stdout=out)
        self.assertIn('Successfully collected all permissions.', out.getvalue())


class CreateRole(TestCase):
    def setUp(self):
        call_command('initialize-status')

    def test_OK(self):
        out = StringIO()
        call_command('create-role', name='all', stdout=out)
        self.assertIn('Role "all" created successfully in status "draft".', out.getvalue())
        self.assertIn('Role "all" successfully changed to status "circulation".', out.getvalue())
        self.assertIn('Role "all" successfully changed to status "productive".', out.getvalue())

    def test_NOK(self):
        out = StringIO()
        err = StringIO()
        call_command('create-role', name='all', stdout=out)
        self.assertIn('Role "all" created successfully in status "draft".', out.getvalue())
        self.assertIn('Role "all" successfully changed to status "circulation".', out.getvalue())
        self.assertIn('Role "all" successfully changed to status "productive".', out.getvalue())
        # second call to verify that not a second can be created in status productive
        call_command('create-role', name='all', stdout=out, stderr=err)
        self.assertIn('Role "all" created successfully in status "draft".', out.getvalue())
        self.assertIn('Error: Role "all" does already exist in status "productive"', err.getvalue())


class CreateSuperuser(TestCase):
    def setUp(self):
        call_command('initialize-status')

    def test_OK(self):
        out = StringIO()
        call_command('create-role', name='all')
        call_command('create-superuser', role='all', username='admin', password='FAH2a28djakd2', stdout=out)
        self.assertIn('Superuser "admin" created successfully.', out.getvalue())

    def test_NOK_no_prod_role(self):
        out = StringIO()
        err = StringIO()
        call_command('create-superuser', role='all', username='admin', password='FAH2a28djakd2', stdout=out, stderr=err)
        self.assertNotIn('Superuser "admin" created successfully.', out.getvalue())
        self.assertIn('Error: Selected role "all" does not exist in status "productive".', err.getvalue())

    def test_NOK_exist(self):
        self.test_OK()
        out = StringIO()
        err = StringIO()
        call_command('create-superuser', role='all', username='admin', password='FAH2a28djakd2', stdout=out, stderr=err)
        self.assertNotIn('Superuser "admin" created successfully.', out.getvalue())
        self.assertIn('Error: User "admin" already exists.', err.getvalue())
