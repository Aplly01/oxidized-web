# encoding: utf-8
require 'sinatra/base'
require 'sinatra/json'
require 'sinatra/url_for'
require 'tilt/haml'
require 'htmlentities'
require 'charlock_holmes'
require 'logger'
require 'rack/session'
require 'securerandom'
require 'yaml'

module Oxidized
  module API
    require 'oxidized/web/version'
    class WebApp < Sinatra::Base
      helpers Sinatra::UrlForHelper
      set :public_folder, proc { File.join(root, 'public') }
      set :haml, { escape_html: false }

      # === НАСТРОЙКИ СЕССИЙ ===
      cfg_secret = begin
        Oxidized.config.web.auth.session_secret.to_s.strip
      rescue
        ''
      end
      session_secret = (cfg_secret.length >= 64) ? cfg_secret : SecureRandom.hex(32)

      enable :sessions
      use Rack::Session::Cookie,
        key: 'oxidized.session',
        path: '/',
        expire_after: 3600,
        secret: session_secret

      # === ПРОВЕРКА АВТОРИЗАЦИИ ===
      before do
        next if request.path_info =~ %r{^/login$|^/logout$|^/favicon|^/images|^/public|\.css$|\.js$}
        auth_cfg = Oxidized.config.web.auth
        next unless auth_cfg.enabled.to_s.strip.downcase == 'true'
        return if session[:user]

        session[:return_to] = request.path_info unless request.xhr?
        redirect url_for('/login')
      end

      # === МАРШРУТЫ ВХОДА ===
      get '/login' do
        redirect url_for('/nodes') if session[:user]
        haml :login, layout: true
      end

      post '/login' do
        username = params[:username]&.strip
        password = params[:password]&.strip

        users_file = Oxidized.config.web.auth.users_file.to_s.strip
        users = File.exist?(users_file) ? YAML.load_file(users_file) : {}

        if users[username] && users[username].to_s.strip == password
          session[:user] = username
          session.delete(:error)
          logger.info "User '#{username}' logged in (local auth)"
          return_to = session.delete(:return_to) || url_for('/nodes')
          redirect return_to
        else
          session[:error] = 'Некорректное имя пользователя или пароль'
          redirect url_for('/login')
        end
      end

      get '/logout' do
        session.clear
        redirect url_for('/login')
      end

      # === ОСНОВНЫЕ МАРШРУТЫ OXIDIZED ===
      get '/' do
        redirect url_for('/nodes')
      end

      get '/favicon.ico' do
        redirect url_for('/images/favicon.ico')
      end

      get '/nodes/:filter/*' do
        value, @json = route_parse params[:splat].first
        @data = nodes.list.select do |node|
          next unless node[params[:filter].to_sym] == value ||
                      (params[:filter].to_sym == :group &&
                       node[params[:filter].to_sym].nil? &&
                       value.to_sym == :default)
          node[:status] = 'never'
          node[:time]   = 'never'
          node[:group]  = 'default' unless node[:group]
          if node[:last]
            node[:status] = node[:last][:status]
            node[:time]   = node[:last][:end]
          end
          node
        end
        out :nodes
      end

      get '/nodes/add' do
        redirect url_for('/nodes') if session[:role] == 'readonly'
        @models = [
          { value: 'ios', label: 'Cisco IOS' },
          { value: 'vrp', label: 'Huawei VRP' },
          { value: 'os10', label: 'Dell OS10' },
          { value: 'os6', label: 'Dell OS6' }
        ]
        haml :add_node, layout: true
      end

      post '/nodes/add' do
        redirect url_for('/nodes') if session[:role] == 'readonly'
  
        node_name = params[:name]&.strip
        node_ip = params[:ip]&.strip
        node_model = params[:model]&.strip
        node_username = params[:username]&.strip
        node_password = params[:password]&.strip
        node_enable = params[:enable]&.strip

  	errors = []
  	errors << "Name is required" unless node_name && !node_name.empty?
  	errors << "Model is required" unless node_model && !node_model.empty?
  	errors << "Username is required" unless node_username && !node_username.empty?
  	errors << "Password is required" unless node_password && !node_password.empty?
  	errors << "Enable password is required" unless node_enable && !node_enable.empty?

  	if errors.any?
          content_type :json
    	  status 400
    	  return { error: errors.join(', ') }.to_json
  	end

  	begin
    	  # Правильное чтение конфига Oxidized
    	  sql_config = Oxidized.config.input.sql
    
    	  # Извлекаем значения правильно
    	  db_host = sql_config.respond_to?(:host) ? sql_config.host.to_s : sql_config['host'].to_s
    	  db_port = sql_config.respond_to?(:port) ? sql_config.port.to_i : (sql_config['port'] || 1433).to_i
    	  db_database = sql_config.respond_to?(:database) ? sql_config.database.to_s : sql_config['database'].to_s
      	  db_user = sql_config.respond_to?(:user) ? sql_config.user.to_s : sql_config['user'].to_s
    	  db_password = sql_config.respond_to?(:password) ? sql_config.password.to_s : sql_config['password'].to_s
    
    	  # Если значения пустые, пробуем альтернативные пути
    	  if db_user.empty? || db_user.start_with?('#<')
      	    db_user = Oxidized.config.input.sql.user.value rescue Oxidized.config.input.sql[:user].to_s
    	  end
    	  if db_password.empty? || db_password.start_with?('#<')
      	    db_password = Oxidized.config.input.sql.password.value rescue Oxidized.config.input.sql[:password].to_s
          end
          if db_host.empty? || db_host.start_with?('#<')
            db_host = Oxidized.config.input.sql.host.value rescue Oxidized.config.input.sql[:host].to_s
          end
          if db_database.empty? || db_database.start_with?('#<')
            db_database = Oxidized.config.input.sql.database.value rescue Oxidized.config.input.sql[:database].to_s
          end

          logger.info "Connecting to DB: host=#{db_host}, port=#{db_port}, database=#{db_database}, user=#{db_user}"

          client = TinyTds::Client.new(
            username: db_user,
            password: db_password,
            host: db_host,
            port: db_port,
            database: db_database
          )

          esc = ->(val) { val.nil? || val.to_s.strip.empty? ? "NULL" : "'#{val.to_s.strip.gsub("'", "''")}'" }
          sql = "INSERT INTO devices (name, ip, model, username, password, enable) VALUES (#{esc[node_name]}, #{esc[node_ip]}, #{esc[node_model]}, #{esc[node_username]}, #{esc[node_password]}, #{esc[node_enable]})"
          client.execute(sql).do
          client.close

          logger.info "Node '#{node_name}' added to MSSQL."
          content_type :json
          status 201
          { message: "Node '#{node_name}' успешно добавлен" }.to_json
        rescue => e
    	  logger.error "Failed to add node: #{e.message}"
          logger.error e.backtrace.join("\n")
          content_type :json
          status 500
          { error: "Database error: #{e.message}" }.to_json
        end
      end

      get '/nodes.?:format?' do
        @data = nodes.list.map do |node|
          node[:status] = 'never'
          node[:time] = 'never'
          node[:group] = 'default' unless node[:group]
          if node[:last]
            node[:status] = node[:last][:status]
            node[:time] = node[:last][:end]
          end
          node
        end
        out :nodes
      end

      post '/nodes/conf_search.?:format?' do
        @to_research = Regexp.new params[:search_in_conf_textbox]
        nodes_list = nodes.list.map
        @nodes_match = []
        nodes_list.each do |n|
          node, @json = route_parse n[:name]
          config = nodes.fetch node, n[:group]
          @nodes_match.push({ node: n[:name], full_name: n[:full_name] }) if config[@to_research]
        end
        @data = @nodes_match
        out :conf_search
      end

      get '/nodes/stats.?:format?' do
        @data = {}
        nodes.each do |node|
          @data[node.name] = node.stats
        end
        out :stats
      end

      get '/reload.?:format?' do
        node = params[:node]
        node ? nodes.load(node) : nodes.load
        @data = node ? "reloaded #{node}" : 'reloaded list of nodes'
        out
      end

      get '/node/fetch/?*?/:node' do
        node, @json = route_parse :node
        group = params['splat'].first
        group = nil if group.empty?
        begin
          @data = nodes.fetch node, group
        rescue NodeNotFound => e
          @data = e.message
        end
        out :text
      end

      get '/node/next/?*?/:node' do
        node, @json = route_parse :node
        nodes.next node
        redirect url_for('/nodes') unless @json
        @data = 'ok'
        out
      end

      put '/node/next/?*?/:node' do
        node, @json = route_parse :node
        opt = JSON.parse request.body.read
        nodes.next node, opt
        redirect url_for('/nodes') unless @json
        @data = 'ok'
        out
      end

      get '/node/show/:node' do
        node, @json = route_parse :node
        @data = filter_node_vars(nodes.show(node))
        out :node
      end

      get '/node/version.?:format?' do
        @data = nil
        @group = nil
        @node = nil
        node_full = params[:node_full]
        if node_full.include? '/'
          node_full = node_full.rpartition('/')
          @group = node_full[0]
          @node = node_full[2]
          @data = nodes.version @node, @group
        else
          @node = node_full
          @data = nodes.version @node, nil
        end
        out :versions
      end

      get '/node/version/view.?:format?' do
        node, @json = route_parse :node
        @info = {
          node: node,
          group: params[:group],
          oid: params[:oid],
          time: Time.at(params[:epoch].to_i),
          num: params[:num]
        }
        the_data = nodes.get_version node, @info[:group], @info[:oid]
        if %w[json text].include?(params[:format])
          @data = the_data
        else
          @data = HTMLEntities.new.encode(convert_to_utf8(the_data))
        end
        out :version
      end

      get '/node/version/diffs' do
        node, @json = route_parse :node
        @info = { node: node,
                  group: params[:group],
                  oid: params[:oid],
                  time: Time.at(params[:epoch].to_i),
                  num: params[:num],
                  num2: (params[:num].to_i - 1) }
        group = nil
        group = @info[:group] if @info[:group] != ''
        @oids_dates = nodes.version node, group
        if params[:oid2]
          @info[:oid2] = params[:oid2]
          oid2 = nil
          num = @oids_dates.count + 1
          @oids_dates.each do |x|
            num -= 1
            next unless x[:oid].to_s == params[:oid2]
            oid2 = x[:oid]
            @info[:num2] = num
            break
          end
          @data = nodes.get_diff node, @info[:group], @info[:oid], oid2
        else
          @data = nodes.get_diff node, @info[:group], @info[:oid], nil
        end
        @stat = %w[null null]
        if @data != 'no diffs' && !@data.nil?
          @stat = @data[:stat]
          @data = @data[:patch]
        else
          @data = 'No diff available'
        end
        @diff = diff_view @data
        out :diffs
      end

      post '/node/version/diffs' do
        redirect url_for("/node/version/diffs?node=#{params[:node]}&group=#{params[:group]}&oid=#{params[:oid]}&epoch=#{params[:epoch]}&num=#{params[:num]}&oid2=#{params[:oid2]}")
      end

      HTML_ESCAPE = { '&' => '&amp;', '<' => '&lt;', '>' => '&gt;', '"' => '&quot;', "'" => '&#39;' }.freeze
      HTML_ESCAPE_ONCE_REGEX = /['" &<>]|&(?!([a-zA-Z]+|#(\d+|[xX][0-9a-fA-F]+);))/

      private

      def out(template = :text)
        if @json || params[:format] == 'json'
          json @data.is_a?(String) ? @data.lines : @data
        elsif template == :text || params[:format] == 'text'
          content_type :text
          @data
        else
          haml template, layout: true
        end
      end

      def nodes
        settings.nodes
      end

      def route_parse(param)
        json = false
        e = param.respond_to?(:to_str) ? param.split('.') : params[param].split('.')
        if e.last == 'json'
          e.pop
          json = true
        end
        [e.join('.'), json]
      end

      def time_from_now(date)
        return "no time specified" if date.nil?
        raise "time_from_now needs a Time object" unless date.instance_of? Time
        t = (Time.now - date).to_i
        mm, ss = t.divmod(60)
        hh, mm = mm.divmod(60)
        dd, hh = hh.divmod(24)
        if dd.positive?
          "#{dd} days #{hh} hours ago"
        elsif hh.positive?
          "#{hh} hours #{mm} min ago"
        else
          "#{mm} min #{ss} sec ago"
        end
      end

      def diff_view(diff)
        old_diff, new_diff = [], []
        HTMLEntities.new.encode(convert_to_utf8(diff)).each_line do |line|
          if /^\+/.match?(line)
            new_diff << line
          elsif /^-/.match?(line)
            old_diff << line
          else
            new_diff << line
            old_diff << line
          end
        end
        length_o, length_n = old_diff.count, new_diff.count
        (0..[length_o, length_n].max).each do |i|
          break if i > [length_o, length_n].min
          if /^-.*/.match?(old_diff[i]) && !/^\+.*/.match?(new_diff[i])
            new_diff.insert(i, " &nbsp;\n")
            length_n += 1
          elsif !/^-.*/.match?(old_diff[i]) && /^\+.*/.match?(new_diff[i])
            old_diff.insert(i, " &nbsp;\n")
            length_o += 1
          end
        end
        { old_diff: old_diff, new_diff: new_diff }
      end

      def convert_to_utf8(text)
        detection = CharlockHolmes::EncodingDetector.detect(text)
        detection[:type] == :text ? CharlockHolmes::Converter.convert(text, detection[:encoding], 'UTF-8') : 'The text contains binary values - cannot display'
      end

      def filter_node_vars(serialized_node)
        data = Marshal.load(Marshal.dump(serialized_node))
        data[:vars] = data[:vars].transform_keys(&:to_s)
        hide_node_vars = settings.configuration[:hide_node_vars].map(&:to_s)
        if data[:vars].is_a?(Hash) && hide_node_vars&.any?
          hide_node_vars.each { |key| data[:vars][key] = '<hidden>' if data[:vars].has_key?(key) }
        end
        data
      end
    end
  end
end
