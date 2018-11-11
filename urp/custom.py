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


class UserName(object):
    def __init__(self, first_name, last_name, existing_users):
        self.first_name = first_name.lower()
        self.last_name = last_name.lower()
        self.length = len(first_name)
        self._tmp_first_name = str()
        self.existing = existing_users

    @property
    def tmp_first_name(self):
        return self._tmp_first_name

    @tmp_first_name.setter
    def tmp_first_name(self, value):
        self._tmp_first_name = value

    @property
    def algorithm(self):
        """Function to generate unique user names.

            :returns: username
            :rtype: str
        """
        for x in range(self.length):
            first_name = '{}{}'.format(self.tmp_first_name, self.first_name[x])
            username = '{}{}'.format(self.last_name, first_name)
            if username in self.existing:
                self.tmp_first_name = first_name
            else:
                return username
        for x in range(1000):
            first_name = '{}{}'.format(self.first_name, x + 1)
            username = '{}{}'.format(self.last_name, first_name)
            if username in self.existing:
                self.tmp_first_name = first_name
            else:
                return username
