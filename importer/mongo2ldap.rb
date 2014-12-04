#!/usr/bin/env ruby -w

require 'net-ldap'
require 'mongo'
require 'json'
include Mongo

mongo_id_root = "543fceb54fd25c0bf570b1fd"
mongo_host = 'localhost'
mongo_db = 'gecoscc'
mongo_port = '27017'
data_types = ['ou', 'user']
ldap_host = '172.17.0.3'
ldap_port = '389'
ldap_auth = 'cn=admin,dc=test,dc=com'
ldap_pw = '1234'
ldap_treebase = "dc=test, dc=com"

#group_base should be created in ldap to fix "posix group" ldap user dependency
group_base = "group1"


# Clase que coge los datos de mongo, los trata y los envia al ldap
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

  def split_data(data, dtype, level_root)
    level = level_root
    a = []
    while level != 0 do
      full_data = data

      count_not_found = 1
      data.each do |v|
        v_hashed = v.to_h
        level_count = v_hashed["path"].split(',').count()
        if level_count == level
          @id_hash.merge!(v_hashed["_id"].to_s => v_hashed["name"])
          level_tree = level_count
          ldapmod(@ldap_host, @ldap_port, @ldap_auth, @ldap_pw, @ldap_treebase, v_hashed, dtype, level_tree) 
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
      v_hashed = v.to_h
      if v_hashed["name"] == name and v_hashed["path"] == path
       
       array_path = v_hashed["path"].split(',')
       # removing 2 first id from path (root and main ou)
       array_path.shift(2)
       array_path.each do |id| 
         @full_data.each do |data_value|
           data_value_h = data_value.to_h
           if data_value_h["_id"].to_s == id and data_value_h["type"] == "ou"
             dn.insert(0, "ou=#{data_value_h["name"]},")
           end
         end
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
             p "La OU ya esta creada"
             mod_ldap_data(ldap, data, treebase, dn)
             check = 1
           end
        end
      end
      if check == 0
        p "Insertamos OU"
        insert_ldap_data(ldap, data, treebase, dn)
      end
    elsif data["type"] == 'user'
      puts "CREAMOS USUARIO" 
    end

  end

  def mod_ldap_data(ldap, data_hashed, treebase, dn)
    puts "modificamos movidas"
  end

  def insert_ldap_data(ldap, data_hashed, treebase, dn)
    puts "insertamos "
    attributes = {}
    if data_hashed["type"] == 'ou'
      if !data_hashed['extra'].empty?; attributes.merge!(:gecosExtra => data_hashed['extra']) ; end
      if !data_hashed['master'].empty?; attributes.merge!(:gecosMaster => data_hashed['master']) ; end
      if !data_hashed['source'].empty?; attributes.merge!(:gecosSource => data_hashed['source']) ; end
      if !data_hashed['master'].empty?; attributes.merge!(:gecosMaster => data_hashed['master']) ; end
      if !data_hashed['name'].empty?; attributes.merge!(:gecosName => data_hashed['name']) ; end
      if !data_hashed['path'].empty?; attributes.merge!(:gecosPath => data_hashed['path']) ; end
      attributes.merge!(:gecosID => data_hashed['_id'].to_s)
      attributes.merge!(:objectclass => ['top','organizationalunit','gecosOU'])
      ldap.add(:dn => dn, :attributes => attributes)
      p ldap.get_operation_result
#    elsif dtype = 'user'
#      p data
#      p dtype
#      p "================="
    end

  end
end

Gecoscc2ldap.new(mongo_id_root, mongo_host, mongo_db, mongo_port, data_types, ldap_host, ldap_port, ldap_auth, ldap_pw, ldap_treebase)
