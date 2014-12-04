import gzip
import tempfile

import ldap
import requests

try:
    from lxml import etree as ET
    ET_KWARGS = {'pretty_print': True}
except ImportError:
    import xml.etree.cElementTree as ET
    ET_KWARGS = {}


LDAP_SERVER_EMG = 'ldap://LDAP_URL:389'
BIND_DN = 'cn=admin,dc=test,dc=com'
BIND_PASS = '****'
BASE_DN = 'dc=test,dc=com'
SEARCH_SCOPE = ldap.SCOPE_SUBTREE

GECOSCC_API_URL = "http://gecoscc/api/ad_import/"  # This is a demo GECOSCC
GECOSCC_API_USERNAME = "adminemergya"
GECOSCC_API_PASSWORD = "adminemergya"
GECOSCC_API_DOMAIN_ID = "5480374100251c1770b7819e"  # Domain id
GECOSCC_API_MASTER = True  # True LDAP is master, False GCC is master


class NoUniqueException(Exception):
    pass


class NoLDAPDataException(Exception):
    pass


def connection_to_ldap():
    try:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
        ldap.set_option(ldap.OPT_REFERRALS, 0)
        lcon = ldap.initialize(LDAP_SERVER_EMG)
        lcon.simple_bind_s(BIND_DN, BIND_PASS)
    except ldap.LDAPError:
        return None
    return lcon


def search(lcon, search_filter, unique=False):
    try:
        ldap_result_id = lcon.search(BASE_DN, SEARCH_SCOPE, search_filter)
        result_set = []
        while 1:
            result_type, result_data = lcon.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                # here you don't have to append to a list
                # you could do whatever you want with the individual entry
                # The appending to list is just for illustration.
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.extend(result_data)
    except ldap.LDAPError, e:
        print e
    if unique:
        if len(result_set) == 1:
            return result_set[0]
        raise NoUniqueException
    return result_set


def check_ldap_data(data):
    if len(data) == 2:
        if isinstance(data[0], basestring) and isinstance(data[1], dict):
            return True
    raise NoLDAPDataException


def get_ldap_cn(data):
    return data[0]


def get_ldap_attr(data, attr, default='', unique=True):
    value = data[1].get(attr, None)
    if value:
        if unique:
            if len(value) == 1:
                return value[0]
            raise NoUniqueException
        return value
    return default


def create_domain_xml(domain):
    check_ldap_data(domain)
    domain_xml = ET.Element('Domain')
    domain_xml.set('ObjectGUID', get_ldap_cn(domain))
    domain_xml.set('DistinguishedName', get_ldap_cn(domain))
    domain_xml.set('Name', get_ldap_attr(domain, 'dc'))
    return domain_xml


def create_subelement_plural(domain_xml, name):
    return ET.SubElement(domain_xml, name)


def create_ou_element(ou, ou_plural):
    check_ldap_data(ou)
    ou_xml = ET.SubElement(ou_plural, 'OrganizationalUnit')
    ou_xml.set('ObjectGUID', get_ldap_cn(ou))
    ou_xml.set('DistinguishedName', get_ldap_cn(ou))
    ou_xml.set('Name', get_ldap_attr(ou, 'ou'))
    ou_xml.set('Description', '')


def create_user_element(user, user_plural, group_index):
    user_xml = ET.SubElement(user_plural, 'User')
    user_xml.set('ObjectGUID', get_ldap_cn(user))
    user_xml.set('DistinguishedName', get_ldap_cn(user))
    user_xml.set('Name', get_ldap_attr(user, 'cn'))
    user_xml.set('PrimaryGroup', '')
    user_xml.set('EmailAddress', '')
    user_xml.set('DisplayName', get_ldap_attr(user, 'givenName'))
    user_xml.set('LastName', get_ldap_attr(user, 'sn'))
    user_xml.set('OfficePhone', '')

    member_xml = ET.SubElement(user_xml, 'MemberOf')
    for gid in get_ldap_attr(user, 'gidNumber', [], unique=False):
        item_xml = ET.SubElement(member_xml, 'Item')
        item_xml.text = get_ldap_cn(group_index[gid])


def create_group_index(groups):
    group_index = {}
    for group in groups:
        gid = get_ldap_attr(group, 'gidNumber')
        if not gid:
            continue
        group_index[gid] = group
    return group_index


def create_group_element(group, group_plural):
    check_ldap_data(group)
    group_xml = ET.SubElement(group_plural, 'Group')
    group_xml.set('ObjectGUID', get_ldap_cn(group))
    group_xml.set('DistinguishedName', get_ldap_cn(group))
    group_xml.set('Name', get_ldap_attr(group, 'cn'))
    group_xml.set('Description', '')


def create_file_and_send(domain_xml):
    tree = ET.ElementTree(domain_xml)
    f_xml = tempfile.NamedTemporaryFile()
    tree.write(f_xml.name, **ET_KWARGS)

    file_zip = tempfile.NamedTemporaryFile()
    f_zip = gzip.open(file_zip.name, 'wb')

    tf_read = open(f_xml.name, 'r')
    f_zip.writelines(tf_read)
    f_zip.close()
    f_zip_read = open(f_zip.name, 'r')

    res = requests.post(GECOSCC_API_URL,
                        files={'media': f_zip_read},
                        headers={'Content-Disposition': 'attachment; filename=media'},
                        auth=(GECOSCC_API_USERNAME,
                              GECOSCC_API_PASSWORD),
                        data={'domainId': GECOSCC_API_DOMAIN_ID,
                              'master': GECOSCC_API_MASTER})
    tf_read.close()
    f_zip_read.close()
    print res.content


def main():
    lcon = connection_to_ldap()
    if not lcon:
        print 'Connection error'
        return 1

    domain = search(lcon, 'objectClass=dcObject', unique=True)
    domain_xml = create_domain_xml(domain)

    ous = search(lcon, 'objectClass=organizationalUnit')

    ou_plural = create_subelement_plural(domain_xml, 'OrganizationalUnits')

    for ou in ous:
        create_ou_element(ou, ou_plural)

    groups = search(lcon, 'objectClass=posixGroup')
    group_index = create_group_index(groups)

    users = search(lcon, 'objectClass=inetOrgPerson')
    user_plural = create_subelement_plural(domain_xml, 'Users')

    for user in users:
        create_user_element(user, user_plural, group_index)

    group_plural = create_subelement_plural(domain_xml, 'Groups')

    for group in groups:
        create_group_element(group, group_plural)

    create_file_and_send(domain_xml)


if __name__ == '__main__':
    main()