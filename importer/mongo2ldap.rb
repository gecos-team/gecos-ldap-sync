#!/usr/bin/env ruby 

require 'net-ldap'
require 'mongo'
require 'json'
include Mongo

mongo_id_root = "54887421e138230df51e66c1"
mongo_host = 'localhost'
mongo_db = 'gecoscc'
mongo_port = '27017'
data_types = ['ou', 'user','computer','group','storage','repository', 'printer']
ldap_host = '172.17.0.14'
ldap_port = '389'
ldap_auth = 'cn=admin,dc=test,dc=com'
ldap_pw = '1234'
ldap_treebase = "dc=test, dc=com"

class Gecoscc2ldap
  def initialize(mongo_id_root,mongo_host, mongo_db, mongo_port, data_types,ldap_host, ldap_port, ldap_auth, ldap_pw, ldap_treebase, id_hash={})
    @mongo_id_root = mongo_id_root
    @mongo_host = mongo_host
    @mongo_db = mongo_db
    @mongo_port = mongo_port
    @data_types = data_types
    @ldap_host = ldap_host
    @ldap_port = ldap_port
    @ldap_auth = ldap_auth
    @ldap_pw = ldap_pw
    @ldap_treebase = ldap_treebase
    @id_hash = id_hash
    @full_data = []
    mongo_conn()
  end

  def mongo_conn()
    level_root = 1
    mongo_client  = MongoClient.new(@mongo_host, @mongo_port)
    db = mongo_client.db(@mongo_db)
    coll = db.collection('nodes')
    @data_types.each do |dtype|
      data = coll.find({:$or => [{:$and => [{:type => dtype},{:path => /#{@mongo_id_root}/}]},{:_id => BSON::ObjectId.from_string(@mongo_id_root)}]}).to_a
      data.each do |v_data|
        h = v_data.to_h
        if h['_id'].to_s == @mongo_id_root
          level_root = h['path'].split(',').count()
        end
      end
      @full_data = data
      split_data(data, dtype, level_root)
    end
  end

  def convert_encoding(array_hashed)
    array_hashed.each_pair do |k,v|
      if v.class == String
        replacements = [ ['í','i'],['á','a'],['é','e'],['ó','o'],['ú','u'],['ñ','n'] ]
        replacements.each {|replacement| v.gsub!(replacement[0], replacement[1])}
      end
    end
    return array_hashed
  end

  def split_data(data, dtype, level_root)
    level = level_root
    checked = []
    while level != 0 do

      count_not_found = 1
      data.each do |v|
        array_hashed = v.to_h
        v_hashed = convert_encoding(array_hashed)
        level_count = v_hashed["path"].split(',').count()
        if (level_count >= level and v_hashed["type"] == "ou") or (level_count >= level and !checked.include?(v_hashed["_id"].to_s))
          @id_hash.merge!(v_hashed["_id"].to_s => v_hashed["name"])
          level_tree = level_count
          ldapmod(@ldap_host, @ldap_port, @ldap_auth, @ldap_pw, @ldap_treebase, v_hashed, dtype, level_tree) 
          checked << v_hashed["_id"].to_s
          count_not_found = 0
        end
      end

      if count_not_found == 1
        level = 0
      else
        level += 1
      end
    end
  end

  def ldapmod(ldap_host, ldap_port, ldap_auth, ldap_pw, ldap_treebase, data_hashed, dtype, level_tree)
    ldap = Net::LDAP.new
    ldap.host = ldap_host
    ldap.port = ldap_port
    ldap.auth(ldap_auth, ldap_pw)
    if ldap.bind
      check_ldap(ldap, ldap_treebase, data_hashed, level_tree)
    else
      puts "##### Auth ERROR #####"
    end
  end

  def build_mongo_dn(name, path, type, treebase)
    dn = treebase
    data = @full_data.to_a
    data.each do |v|
      array_hashed = v.to_h
      v_hashed = convert_encoding(array_hashed)
      if v_hashed["name"] == name and v_hashed["path"] == path
       
       array_path = v_hashed["path"].split(',')
       # removing 2 first id from path (root and main ou)
       array_path.shift(2)
       array_path.each do |id| 
       dn.insert(0, "ou=#{@id_hash[id]},")
       end
      end
    end
    if type == 'ou'
      dn.insert(0, "ou=#{name},")
    else
      dn.insert(0, "cn=#{name},")
    end
    return dn
  end

  def check_ldap(ldap, ldap_treebase, data, level_tree)
    treebase = ldap_treebase.gsub(' ','')
    check = 0

    dn = build_mongo_dn(data["name"], data["path"], data["type"], treebase)
    if data["type"] == 'ou'
      filter = Net::LDAP::Filter.eq('ou', '*')
      ldap.search(:base => ldap_treebase, :filter => filter) do |ldap_object|
        level_ldap = ldap_object.dn
        level_ldap.slice!(",#{treebase}")

        if ldap_object.dn.downcase == dn.downcase
           if data["master"] == "gecos"
             mod_ldap_data(ldap, data, treebase, dn)
             check = 1
           end
        end
      end
      if check == 0
        insert_ldap_data(ldap, data, treebase, dn)
      end
    elsif data["type"] == 'user'
      filter = Net::LDAP::Filter.eq('objectclass', 'inetOrgPerson')
      ldap.search(:base => ldap_treebase, :filter => filter) do |ldap_object|
        level_ldap = ldap_object.dn
        level_ldap.slice!(",#{treebase}")

        if ldap_object.dn.downcase == dn.downcase
           mod_ldap_data(ldap, data, treebase, dn)
           check = 1
        end
      end
      if check == 0
        insert_ldap_data(ldap, data, treebase, dn)
      end
    elsif data["type"] == 'computer'
      filter = Net::LDAP::Filter.eq('objectclass', 'gecosComputer')
      ldap.search(:base => ldap_treebase, :filter => filter) do |ldap_object|
        level_ldap = ldap_object.dn
        level_ldap.slice!(",#{treebase}")

        if ldap_object.dn.downcase == dn.downcase
           mod_ldap_data(ldap, data, treebase, dn)
           check = 1
        end
      end
      if check == 0
        insert_ldap_data(ldap, data, treebase, dn)
      end
    elsif data["type"] == 'group'
      filter = Net::LDAP::Filter.eq('objectclass', 'gecosGroup')
      ldap.search(:base => ldap_treebase, :filter => filter) do |ldap_object|
        level_ldap = ldap_object.dn
        level_ldap.slice!(",#{treebase}")

        if ldap_object.dn.downcase == dn.downcase
           mod_ldap_data(ldap, data, treebase, dn)
           check = 1
        end
      end
      if check == 0
        insert_ldap_data(ldap, data, treebase, dn)
      end
    elsif data["type"] == 'storage'
      filter = Net::LDAP::Filter.eq('objectclass', 'gecosRemoteDir')
      ldap.search(:base => ldap_treebase, :filter => filter) do |ldap_object|
        level_ldap = ldap_object.dn
        level_ldap.slice!(",#{treebase}")

        if ldap_object.dn.downcase == dn.downcase
           mod_ldap_data(ldap, data, treebase, dn)
           check = 1
        end
      end
      if check == 0
        insert_ldap_data(ldap, data, treebase, dn)
      end

    elsif data["type"] == 'repository'
      filter = Net::LDAP::Filter.eq('objectclass', 'gecosRepo')
      ldap.search(:base => ldap_treebase, :filter => filter) do |ldap_object|
        level_ldap = ldap_object.dn
        level_ldap.slice!(",#{treebase}")

        if ldap_object.dn.downcase == dn.downcase
           mod_ldap_data(ldap, data, treebase, dn)
           check = 1
        end
      end
      if check == 0
        insert_ldap_data(ldap, data, treebase, dn)
      end

    elsif data["type"] == 'printer'
      filter = Net::LDAP::Filter.eq('objectclass', 'gecosPrinter')
      ldap.search(:base => ldap_treebase, :filter => filter) do |ldap_object|
        level_ldap = ldap_object.dn
        level_ldap.slice!(",#{treebase}")

        if ldap_object.dn.downcase == dn.downcase
           mod_ldap_data(ldap, data, treebase, dn)
           check = 1
        end
      end
      if check == 0
        insert_ldap_data(ldap, data, treebase, dn)
      end
    end
  end

  def mod_ldap_data(ldap, data_hashed, treebase, dn)
    if data_hashed["type"] == 'ou'
      if !data_hashed['extra'].empty?; ldap.replace_attribute(dn, :GecosExtra ,data_hashed['extra'])  ; end
      if !data_hashed['master'].empty?; ldap.replace_attribute(dn, :GecosMaster ,data_hashed['master']) ; end
      if !data_hashed['source'].empty?; ldap.replace_attribute(dn, :GecosSource ,data_hashed['source']) ; end
      if !data_hashed['name'].empty?; ldap.replace_attribute(dn, :GecosName ,data_hashed['name']) ; end
      if !data_hashed['path'].empty?; ldap.replace_attribute(dn, :GecosPath, data_hashed['path']) ; end
      if !data_hashed['type'].empty?; ldap.replace_attribute(dn, :GecosType, data_hashed['type']) ; end
      ldap.replace_attribute(dn, :GecosId, data_hashed['_id'].to_s) 
    elsif data_hashed['type'] =='user'
      if !data_hashed['name'].empty?; ldap.replace_attribute(dn, :GecosName ,data_hashed['name']) ; end
      if !data_hashed['name'].empty?; ldap.replace_attribute(dn, :sn, data_hashed['name']); end
      if !data_hashed['path'].empty?; ldap.replace_attribute(dn, :GecosPath, data_hashed['path']) ; end
      if !data_hashed['type'].empty?; ldap.replace_attribute(dn, :GecosType, data_hashed['type']) ; end
      ldap.replace_attribute(dn, :GecosId, data_hashed['_id'].to_s)
    elsif data_hashed['type'] =='computer'
      if !data_hashed['name'].empty?; ldap.replace_attribute(dn, :GecosName ,data_hashed['name']) ; end
      if !data_hashed['name'].empty?; ldap.replace_attribute(dn, :cn ,data_hashed['name']) ; end
      if !data_hashed['path'].empty?; ldap.replace_attribute(dn, :GecosPath, data_hashed['path']) ; end
      if !data_hashed['type'].empty?; ldap.replace_attribute(dn, :GecosType, data_hashed['type']) ; end
      if !data_hashed['family'].empty?; ldap.replace_attribute(dn, :gecosFamily, data_hashed['family']); end
      if !data_hashed['node_chef_id'].empty?; ldap.replace_attribute(dn, :gecosNodeChefId, data_hashed['node_chef_id']); end
      ldap.replace_attribute(dn, :GecosId, data_hashed['_id'].to_s)
    elsif data_hashed['type'] =='group'
      if !data_hashed['name'].empty?; ldap.replace_attribute(dn, :GecosName ,data_hashed['name']) ; end
      if !data_hashed['name'].empty?; ldap.replace_attribute(dn, :cn ,data_hashed['name']) ; end
      if !data_hashed['path'].empty?; ldap.replace_attribute(dn, :GecosPath, data_hashed['path']) ; end
      if !data_hashed['type'].empty?; ldap.replace_attribute(dn, :GecosType, data_hashed['type']) ; end
      if !data_hashed['members'].empty?; ldap.replace_attribute(dn, :gecosMembers, data_hashed['members'].to_s); end
      ldap.replace_attribute(dn, :GecosId, data_hashed['_id'].to_s)
    elsif data_hashed['type'] =='storage'
      if !data_hashed['name'].empty?; ldap.replace_attribute(dn, :GecosName ,data_hashed['name']) ; end
      if !data_hashed['name'].empty?; ldap.replace_attribute(dn, :cn ,data_hashed['name']) ; end
      if !data_hashed['path'].empty?; ldap.replace_attribute(dn, :GecosPath, data_hashed['path']) ; end
      if !data_hashed['type'].empty?; ldap.replace_attribute(dn, :GecosType, data_hashed['type']) ; end
      if !data_hashed['uri'].empty?; ldap.replace_attribute(dn, :gecosRemoteDiskUri, data_hashed['uri']); end
      ldap.replace_attribute(dn, :GecosId, data_hashed['_id'].to_s)
    elsif data_hashed['type'] =='repository'
      if !data_hashed['name'].empty?; ldap.replace_attribute(dn, :GecosName ,data_hashed['name']) ; end
      if !data_hashed['name'].empty?; ldap.replace_attribute(dn, :cn ,data_hashed['name']) ; end
      if !data_hashed['path'].empty?; ldap.replace_attribute(dn, :GecosPath, data_hashed['path']) ; end
      if !data_hashed['type'].empty?; ldap.replace_attribute(dn, :GecosType, data_hashed['type']) ; end
      if !data_hashed['key_server'].empty?; ldap.replace_attribute(dn, :gecosRepoKeyServer, data_hashed['key_server']); end
      if !data_hashed['uri'].empty?; ldap.replace_attribute(dn, :gecosRepoUri, data_hashed['uri']); end
      if !data_hashed['components'].empty?; ldap.replace_attribute(dn, :gecosRepoComponents, data_hashed['components'].to_s); end
      if !data_hashed['repo_key'].empty?; ldap.replace_attribute(dn, :gecosRepoKey, data_hashed['repo_key']); end
      if !data_hashed['distribution'].empty?; ldap.replace_attribute(dn, :gecosRepoDistribution, data_hashed['distribution']); end
      ldap.replace_attribute(dn, :GecosId, data_hashed['_id'].to_s)
    elsif data_hashed['type'] =='printer'
      if !data_hashed['name'].empty?; ldap.replace_attribute(dn, :GecosName ,data_hashed['name']) ; end
      if !data_hashed['name'].empty?; ldap.replace_attribute(dn, :cn ,data_hashed['name']) ; end
      if !data_hashed['path'].empty?; ldap.replace_attribute(dn, :GecosPath, data_hashed['path']) ; end
      if !data_hashed['type'].empty?; ldap.replace_attribute(dn, :GecosType, data_hashed['type']) ; end
      if !data_hashed['description'].empty?; ldap.replace_attribute(dn, :gecosPrinterDesc, data_hashed['description']); end
      if !data_hashed['printtype'].empty?; ldap.replace_attribute(dn, :gecosPrinterPrinttype, data_hashed['printtype']); end
      if !data_hashed['location'].empty?; ldap.replace_attribute(dn, :gecosPrinterLocation, data_hashed['location']); end
      if !data_hashed['uri'].empty?; ldap.replace_attribute(dn, :gecosPrinterUri, data_hashed['uri']); end
      if !data_hashed['connection'].empty?; ldap.replace_attribute(dn, :gecosPrinterConn, data_hashed['connection']); end
      if !data_hashed['model'].empty?; ldap.replace_attribute(dn, :gecosPrinterMod, data_hashed['model']); end
      if !data_hashed['ppd_uri'].empty?; ldap.replace_attribute(dn, :gecosPrinterPpduri, data_hashed['ppd_uri']); end
      if !data_hashed['type'].empty?; ldap.replace_attribute(dn, :gecosPrinterType, data_hashed['type']); end
      if !data_hashed['serial'].empty?; ldap.replace_attribute(dn, :gecosPrinterSerial, data_hashed['serial']); end
      if !data_hashed['registry'].empty?; ldap.replace_attribute(dn, :gecosPrinterRegistry, data_hashed['registry']); end
      if !data_hashed['manufacturer'].empty?; ldap.replace_attribute(dn, :gecosPrinterManuf, data_hashed['manufacturer']); end
      ldap.replace_attribute(dn, :GecosId, data_hashed['_id'].to_s)
    end

  end

  def insert_ldap_data(ldap, data_hashed, treebase, dn)
    attributes = {}
    if data_hashed["type"] == 'ou'

      if @mongo_id_root == data_hashed['_id'].to_s
        if !data_hashed['master'].empty?; attributes.merge!(:gecosMaster => data_hashed['master']) ; end
        if !data_hashed['source'].empty?; attributes.merge!(:gecosSource => data_hashed['source']) ; end
      end
      if !data_hashed['extra'].empty?; attributes.merge!(:gecosExtra => data_hashed['extra']) ; end
      if !data_hashed['name'].empty?; attributes.merge!(:gecosName => data_hashed['name']) ; end
      if !data_hashed['path'].empty?; attributes.merge!(:gecosPath => data_hashed['path']) ; end
      if !data_hashed['type'].empty?; attributes.merge!(:gecosType => data_hashed['type']) ; end
      attributes.merge!(:gecosID => data_hashed['_id'].to_s)
      attributes.merge!(:objectclass => ['top','organizationalunit','gecoscc', 'gecosOU'])
      ldap.add(:dn => dn, :attributes => attributes)
      #p ldap.get_operation_result
    elsif data_hashed['type'] == 'user'
      if !data_hashed['name'].empty?; attributes.merge!(:gecosName => data_hashed['name']) ; end
      if !data_hashed['name'].empty?; attributes.merge!(:sn => data_hashed['name']) ; end
      if !data_hashed['type'].empty?; attributes.merge!(:gecosType => data_hashed['type']) ; end
      if !data_hashed['path'].empty?; attributes.merge!(:gecosPath => data_hashed['path']) ; end
      attributes.merge!(:gecosID => data_hashed['_id'].to_s)
      attributes.merge!(:objectclass => ['inetOrgPerson','top','gecoscc'])
      ldap.add(:dn => dn, :attributes => attributes)
      #p ldap.get_operation_result
   elsif data_hashed['type'] == 'computer'
      if !data_hashed['name'].empty?; attributes.merge!(:gecosName => data_hashed['name']) ; end
      if !data_hashed['family'].empty?; attributes.merge!(:gecosFamily => data_hashed['family']) ; end
      if !data_hashed['type'].empty?; attributes.merge!(:gecosType => data_hashed['type']) ; end
      if !data_hashed['node_chef_id'].empty?; attributes.merge!(:gecosNodeChefId => data_hashed['node_chef_id']) ; end
      if !data_hashed['path'].empty?; attributes.merge!(:gecosPath => data_hashed['path']) ; end
      attributes.merge!(:cn => data_hashed['name'])
      attributes.merge!(:gecosID => data_hashed['_id'].to_s)
      attributes.merge!(:objectclass => ['olcSchemaConfig','gecoscc','gecosComputer'])
      ldap.add(:dn => dn, :attributes => attributes)
      #p ldap.get_operation_result
   elsif data_hashed['type'] == 'group'
      if !data_hashed['name'].empty?; attributes.merge!(:gecosName => data_hashed['name']) ; end
      if !data_hashed['path'].empty?; attributes.merge!(:gecosPath => data_hashed['path']) ; end
      if !data_hashed['type'].empty?; attributes.merge!(:gecosType => data_hashed['type']) ; end
      if !data_hashed['members'].empty?; attributes.merge!(:gecosMembers => data_hashed['members'].to_s) ; end
      attributes.merge!(:cn => data_hashed['name'])
      attributes.merge!(:gecosID => data_hashed['_id'].to_s)
      attributes.merge!(:objectclass => ['olcSchemaConfig','gecoscc','gecosGroup'])
      ldap.add(:dn => dn, :attributes => attributes)
      #p ldap.get_operation_result
   elsif data_hashed['type'] == 'storage'
      if !data_hashed['name'].empty?; attributes.merge!(:gecosName => data_hashed['name']) ; end
      if !data_hashed['path'].empty?; attributes.merge!(:gecosPath => data_hashed['path']) ; end
      if !data_hashed['type'].empty?; attributes.merge!(:gecosType => data_hashed['type']) ; end
      if !data_hashed['uri'].empty?; attributes.merge!(:gecosRemoteDiskUri => data_hashed['uri']) ; end
      attributes.merge!(:cn => data_hashed['name'])
      attributes.merge!(:gecosID => data_hashed['_id'].to_s)
      attributes.merge!(:objectclass => ['olcSchemaConfig','gecoscc','gecosRemoteDisk'])
      ldap.add(:dn => dn, :attributes => attributes)
      #p ldap.get_operation_result
   elsif data_hashed['type'] == 'repository'
      if !data_hashed['name'].empty?; attributes.merge!(:gecosName => data_hashed['name']) ; end
      if !data_hashed['path'].empty?; attributes.merge!(:gecosPath => data_hashed['path']) ; end
      if !data_hashed['type'].empty?; attributes.merge!(:gecosType => data_hashed['type']) ; end
      if !data_hashed['uri'].empty?; attributes.merge!(:gecosRepoUri => data_hashed['uri']) ; end
      if !data_hashed['key_server'].empty?; attributes.merge!(:gecosRepoKeyServer => data_hashed['key_server']) ; end
      if !data_hashed['components'].empty?; attributes.merge!(:gecosRepoComponents => data_hashed['components'].to_s) ; end
      if !data_hashed['repo_key'].empty?; attributes.merge!(:gecosRepoKey => data_hashed['repo_key']) ; end
      if !data_hashed['distribution'].empty?; attributes.merge!(:gecosRepoDistribution => data_hashed['distribution']) ; end
      attributes.merge!(:cn => data_hashed['name'])
      attributes.merge!(:gecosID => data_hashed['_id'].to_s)
      attributes.merge!(:objectclass => ['olcSchemaConfig','gecoscc','gecosRepo'])
      ldap.add(:dn => dn, :attributes => attributes)
      #p ldap.get_operation_result
   elsif data_hashed['type'] == 'printer'
      if !data_hashed['name'].empty?; attributes.merge!(:gecosName => data_hashed['name']) ; end
      if !data_hashed['path'].empty?; attributes.merge!(:gecosPath => data_hashed['path']) ; end
      if !data_hashed['type'].empty?; attributes.merge!(:gecosType => data_hashed['type']) ; end
      if !data_hashed['description'].empty?; attributes.merge!(:gecosPrinterDesc => data_hashed['description']) ; end
      if !data_hashed['printtype'].empty?; attributes.merge!(:gecosPrinterPrinttype => data_hashed['printtype']) ; end
      if !data_hashed['location'].empty?; attributes.merge!(:gecosPrinterLocation => data_hashed['location']) ; end
      if !data_hashed['uri'].empty?; attributes.merge!(:gecosPrinterUri => data_hashed['uri']) ; end
      if !data_hashed['connection'].empty?; attributes.merge!(:gecosPrinterConn => data_hashed['connection']) ; end
      if !data_hashed['model'].empty?; attributes.merge!(:gecosPrinterMod => data_hashed['model']) ; end
      if !data_hashed['ppd_uri'].empty?; attributes.merge!(:gecosPrinterPpduri => data_hashed['ppd_uri']) ; end
      if !data_hashed['type'].empty?; attributes.merge!(:gecosPrinterType => data_hashed['type']) ; end
      if !data_hashed['serial'].empty?; attributes.merge!(:gecosPrinterSerial => data_hashed['serial']) ; end
      if !data_hashed['registry'].empty?; attributes.merge!(:gecosPrinterRegistry => data_hashed['registry']) ; end
      if !data_hashed['manufacturer'].empty?; attributes.merge!(:gecosPrinterManuf => data_hashed['manufacturer']) ; end
      attributes.merge!(:cn => data_hashed['name'])
      attributes.merge!(:gecosID => data_hashed['_id'].to_s)
      attributes.merge!(:objectclass => ['olcSchemaConfig','gecoscc','gecosPrinter'])
      ldap.add(:dn => dn, :attributes => attributes)
      #p ldap.get_operation_result
    end
  end
end

Gecoscc2ldap.new(mongo_id_root, mongo_host, mongo_db, mongo_port, data_types, ldap_host, ldap_port, ldap_auth, ldap_pw, ldap_treebase)
