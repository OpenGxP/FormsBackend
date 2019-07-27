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

# public
from urp.views.public.login import login_view
from urp.views.public.password_reset import request_password_reset_email_view, password_reset_email_view

from urp.views.views import *

from urp.views.private.meta import meta_list
from urp.views.private.spaces import spaces_list, spaces_detail, spaces_log_list
from urp.views.private.lists import lists_list, lists_detail, lists_status, lists_log_list
from urp.views.private.logout import logout_view, logout_auto_view
