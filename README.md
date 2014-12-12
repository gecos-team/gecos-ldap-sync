gecos-ldap-sync
===============


Importer
========

First steps.

#Ruby version

Importer code should works on ruby 2.x

#Code
The importer code is inside 'importer' subdir

#Ldap
The schemas must add to a Openldap instance, the schema is inside ldap_schemas directory

#Installation
Just run "bundle" inside importer directory, all dependencies

#Configuration

you should configure the next variables in the top of the file mongo2ldap.rb

mongo_id_root: the ID, in String mode, of the domain in mongo you want import into ldap, its should be something like 54887421e138230df51e66c1
mongo_host: The MongoDB host IP/DNS 
mongo_db: The MongoDB Database
mongo_port: The Mongo Port
data_types: its must be and array with the data types you want import in ldap, something like  ['ou', 'user','computer','group','storage','repository', 'repository']
ldap_host: The LDAP host
ldap_port: The LDAP port
ldap_auth: The LDAP auth
ldap_pw: The LDAP password
ldap_treebase: The base of the tree in ldap to start importing data, like "dc=test, dc=com"


