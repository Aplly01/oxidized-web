#!/usr/bin/env ruby
# Создаёт первого администратора в таблице users MSSQL
# Использование: ruby create_admin.rb admin MySecurePass123 "Admin User"

require 'tiny_tds'
require 'bcrypt'
require 'yaml'

# Загружаем конфиг Oxidized для получения параметров БД
oxidized_config = YAML.load_file(File.expand_path('~/.config/oxidized/config'))
sql_cfg = oxidized_config['input']['sql']

client = TinyTds::Client.new(
  username: sql_cfg['user'],
  password: sql_cfg['password'],
  host:     sql_cfg['host'],
  port:     sql_cfg['port'] || 1433,
  database: sql_cfg['database']
)

username = ARGV[0] || 'admin'
password = ARGV[1] || 'oxidized#968'
full_name = ARGV[2] || 'Administrator'

if username.length < 3
  puts "❌ Username too short (min 3 chars)"
  exit 1
end

if password.length < 8
  puts "❌ Password too short (min 8 chars)"
  exit 1
end

password_hash = BCrypt::Password.create(password, cost: 12)

begin
  client.execute(
    "INSERT INTO users (username, password_hash, full_name, role, active) 
     VALUES (@username, @hash, @name, @role, 1)",
    {
      username: { type: :string, value: username },
      hash:     { type: :string, value: password_hash },
      name:     { type: :string, value: full_name },
      role:     { type: :string, value: 'admin' }
    }
  ).do
  puts "✅ User '#{username}' created successfully!"
rescue TinyTds::Error => e
  if e.message.include?('violation of UNIQUE KEY')
    puts "⚠️ User '#{username}' already exists"
  else
    puts "❌ Database error: #{e.message}"
    exit 1
  end
ensure
  client.close
end
