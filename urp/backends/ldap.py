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

# python imports
import ssl
import os
from stat import S_IWRITE, S_IRUSR

# django imports
from django.core.exceptions import ValidationError
from django.conf import settings

# ldap imports
from ldap3 import Server, Connection
from ldap3.core import exceptions
from ldap3.core.tls import Tls
from ldap3.utils.log import set_library_log_detail_level

# define logger
set_library_log_detail_level(settings.LDAP_LOG_LEVEL)


def init_server(host, port, use_ssl, certificate=None):
    # write certificate to server
    cert_file = '{}/{}_ca_certs_file.pem'.format(settings.DATA_DIR, host)
    if certificate:
        with open(cert_file, 'w') as file:
            file.write(certificate)
        os.chmod(cert_file, S_IWRITE | S_IRUSR)
    try:
        if use_ssl:
            # generate tls object
            tls = Tls(validate=ssl.CERT_REQUIRED,
                      ca_certs_file='{}/{}_ca_certs_file.pem'.format(settings.DATA_DIR, host),
                      version=ssl.PROTOCOL_TLS)

            return Server(host=host,
                          port=port,
                          tls=tls,
                          use_ssl=use_ssl,
                          connect_timeout=settings.LDAP_SERVER_CONNECTION_TIMEOUT)
        return Server(host=host,
                      port=port,
                      use_ssl=use_ssl,
                      connect_timeout=settings.LDAP_SERVER_CONNECTION_TIMEOUT)
    except exceptions.LDAPSSLConfigurationError as e:
        raise ValidationError('LDAP Error: "{}"'.format(e))
    except exceptions.LDAPInvalidPortError as e:
        raise ValidationError('LDAP Error: "{}"'.format(e))
    except exceptions.LDAPInvalidServerError as e:
        raise ValidationError('LDAP Error: "{}"'.format(e))
    except exceptions.LDAPInvalidTlsSpecificationError as e:
        raise ValidationError('LDAP Error: "{}"'.format(e))
    except exceptions.LDAPSocketOpenError as e:
        raise ValidationError('LDAP Error: "{}"'.format(e))


def connect(server, bind_dn, password):
    try:
        return Connection(server=server,
                          user=bind_dn,
                          password=password,
                          auto_bind=settings.LDAP_CON_AUTO_BIN,
                          version=settings.LDAP_CON_VERSION,
                          authentication=settings.LDAP_CON_AUTHENTICATE,
                          read_only=settings.LDAP_CON_READ_ONLY)
    except exceptions.LDAPBindError as e:
        raise ValidationError('LDAP Error: "{}"'.format(e))
    # FO-172: catch exception for invalid server certificate and raise validation error
    except exceptions.LDAPSocketOpenError as e:
        raise ValidationError('LDAP Error: "{}"'.format(e))


def search(con, base, ldap_filter, attributes):
    try:
        con.search(search_base=base,
                   search_filter=ldap_filter,
                   search_scope=settings.LDAP_SEARCH_SCOPE,
                   attributes=attributes)
    except exceptions.LDAPInvalidFilterError as e:
        raise ValidationError('LDAP Error: "{}"'.format(e))
    except exceptions.LDAPAttributeError as e:
        raise ValidationError('LDAP Error: "{}"'.format(e))


def server_check(data):
    try:
        server = init_server(host=data['host'], port=data['port'], use_ssl=data['ssl_tls'],
                             certificate=data['certificate'])
    except KeyError:
        server = init_server(host=data['host'], port=data['port'], use_ssl=data['ssl_tls'])
    if not server.check_availability():
        raise ValidationError('LDAP server <{}> not available at port <{}>.'.format(data['host'], data['port']))

    con = connect(server=server, bind_dn=data['bindDN'], password=data['password'])
    # mandatory field username must be filled
    attributes = [data['attr_username']]
    if 'attr_email' in data:
        attributes.append(data['attr_email'])
    if 'attr_surname' in data:
        attributes.append(data['attr_username'])
    if 'attr_forename' in data:
        attributes.append(data['attr_forename'])
    search(con=con, base=data['base_user'], ldap_filter=data['filter_user'], attributes=attributes)
    if not con.response and con.result['description'] == 'success':
        raise ValidationError('LDAP search failed. False base_user or filter_user')

    if 'base_group' in data:
        if data['base_group']:
            search(con=con, base=data['base_group'], ldap_filter=data['filter_group'], attributes=[data['attr_group']])
            if not con.response and con.result['description'] == 'success':
                raise ValidationError('LDAP search failed. False base_group or filter_group')
