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
GECOSCC_API_DOMAIN_ID = "547f2e4e00251c336d4cabbd"  # Domain id
GECOSCC_API_MASTER = False  # True LDAP is master, False GCC is master


class NoUniqueException(Exception):
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


def search(search_filter, unique=False):
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


def create_domain_xml(domain):
    domain_xml = ET.Element('Domain')
    domain_xml.set('ObjectGUID', domain[0])
    domain_xml.set('DistinguishedName', domain[0])
    domain_xml.set('Name', domain[1]['dc'][0])
    return domain_xml


def create_subelement_plural(domain_xml, name):
    return ET.SubElement(domain_xml, name)


def create_ou_element(ou, ou_plural):
    ou_xml = ET.SubElement(ou_plural, 'OrganizationalUnit')
    ou_xml.set('ObjectGUID', ou[0])
    ou_xml.set('DistinguishedName', ou[0])
    ou_xml.set('Name', ou[1]['ou'][0])
    ou_xml.set('Description', '')


def create_user_element(user, user_plural):
    user_xml = ET.SubElement(user_plural, 'User')
    user_xml.set('ObjectGUID', user[0])
    user_xml.set('DistinguishedName', ou[0])
    user_xml.set('Name', user[1]['cn'][0])
    user_xml.set('PrimaryGroup', '')
    user_xml.set('EmailAddress', '')
    user_xml.set('DisplayName', '')
    user_xml.set('OfficePhone', '')


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

if __name__ == '__main__':
    lcon = connection_to_ldap()
    if not lcon:
        print 'Connection error'

    domain = search('objectClass=dcObject', unique=True)
    domain_xml = create_domain_xml(domain)

    ous = search('objectClass=organizationalUnit')
    ou_plural = create_subelement_plural(domain_xml, 'OrganizationalUnits')

    for ou in ous:
        create_ou_element(ou, ou_plural)

    users = search('objectClass=inetOrgPerson')
    user_plural = create_subelement_plural(domain_xml, 'Users')

    for user in users:
        create_user_element(user, user_plural)

    create_file_and_send(domain_xml)
