require 'fileutils'
require 'openssl'
require 'digest/sha1'
require 'optparse'

require 'rubygems'
require 'highline'
require 'session'


##
# Yak is a simple command line app to store and retrieve passwords securely.
# Retrieved passwords get copied to the clipboard by default.
# Config can be set in ~/.yakrc:
#   :session: 30
# Session is the length of time in seconds that Yak will remember the
# master password. If using sessions is not desired, set:
#   :session: false
# To always set the password by default, use:
#   :password: plain_text_password
# To turn off password confirmation prompts:
#   :confirm_prompt: false

class Yak

  VERSION = "1.0.0"

  DEFAULT_CONFIG = {:session => 30}

  ##
  # Run Yak with argv:
  #   Yak.run %w{key}
  #   Yak.run %w{--add key}
  #   ...

  def self.run argv=ARGV
    config = DEFAULT_CONFIG.merge load_config

    options = parse_args argv

    yak = new `whoami`.chomp, config

    args = [options[:action], yak, options[:key], options[:value]].compact

    self.send(*args)

  rescue OpenSSL::CipherError => e
    $stderr << "Bad password.\n"
    exit 1
  end


  ##
  # Load the ~/.yakrc file and return. Creates ~/.yakrc with the
  # default config if missing.

  def self.load_config
    config_file = File.expand_path "~/.yakrc"

    if !File.file?(config_file)
      File.open(config_file, "w+"){|f| f.write DEFAULT_CONFIG.to_yaml }
      $stderr << "Created Yak config file #{config_file}\n"
    end

    YAML.load_file config_file
  end


  def self.remove yak, name
    yak.remove name
    yak.write_data
  end


  def self.store yak, name, value=nil
    yak.store name, value
    yak.write_data
  end


  def self.retrieve yak, name
    send_to_clipboard yak.retrieve(name)
  end


  def self.list yak, name=nil
    key_regex = /#{name || ".+"}/

    yak.data.each do |key, value|
      $stdout << "#{key}: #{value}\n" if key =~ key_regex
    end
  end


  def self.new_password yak, value=nil
    yak.new_password value
    yak.write_data
    yak.start_session
  end


  def self.send_to_clipboard string
    copy_cmd = case RUBY_PLATFORM
               when /darwin/
                 "echo -n \"#{string}\" | pbcopy"
               when /linux/
                 "echo -n \"#{string}\" | xclip"
               when /cigwin/
                 "echo -n \"#{string}\" | putclip"
               when /(win|mingw)/
                 "echo \"#{string}\" | clip"
               else
                 $stderr << "No clipboad cmd for platform #{RUBY_PLATFORM}\n"
                 exit 1
               end

    Session::Bash.new.execute copy_cmd
  end


  def self.parse_args argv
    options = {}

    opts = OptionParser.new do |opt|
      opt.program_name = File.basename $0
      opt.version = VERSION
      opt.release = nil

      opt.banner = <<-EOF
#{opt.program_name} is a simple app to store and retrieve passwords securely.
Retrieved passwords get copied to the clipboard by default.

  Usage:
    #{opt.program_name} [options] [key] [password]

  Examples:
    #{opt.program_name} -a gmail [password]
    #{opt.program_name} gmail
    #{opt.program_name} -r gmail
    #{opt.program_name} --list
    
  Options:
      EOF

      opt.on('-a', '--add KEY',
             'Add a new password for a given key') do |key|
        options[:action] = :store
        options[:key]    = key
      end

      opt.on('-r', '--remove KEY',
             'Remove the password for a given key') do |key|
        options[:action] = :remove
        options[:key]    = key
      end

      opt.on('-l', '--list [REGEX]',
             'List key/password pairs to the stdout') do |key|
        options[:action] = :list
        options[:key]    = key
      end

      opt.on('-n', '--new-password',
             'Update the password used for encryption') do |value|
        options[:action] = :new_password
      end
    end

    opts.parse! argv

    options[:action] ||= :retrieve
    options[:key]    ||= argv.shift
    options[:value]  ||= argv.shift

    options
  end


  attr_reader :user, :data

  ##
  # Create a new Yak instance for a given user:
  #   Yak.new "my_user"
  #   Yak.new "my_user", :session => 10
  #   Yak.new `whoami`.chomp, :session => false

  def initialize user, options={}
    @user     = user
    @input    = HighLine.new $stdin, $stderr

    @confirm_prompt = true
    @confirm_prompt = options[:confirm_prompt] if
      options.has_key? :confirm_prompt

    @yak_dir = File.expand_path "~#{@user}/.yak"
    FileUtils.mkdir @yak_dir unless File.directory? @yak_dir

    @pid_file      = File.join @yak_dir, "pid"
    @password_file = File.join @yak_dir, "password"
    @data_file     = File.join @yak_dir, "data"

    @session_pid = nil
    @session_pid = File.read(@pid_file).to_i if File.file? @pid_file

    @password = get_password options[:password]

    @cipher = OpenSSL::Cipher::Cipher.new "aes-256-cbc"

    @session_length = options.has_key?(:session) ? options[:session] : 30

    connect_data
    start_session
  end


  ##
  # Start a new session during which Yak will remember the user's password.

  def start_session
    return unless @session_length

    end_session if has_session?

    pid = fork do
      sleep @session_length
      FileUtils.rm_f [@password_file, @pid_file]
    end

    File.open(@pid_file,      "w+"){|f| f.write pid }
    File.open(@password_file, "w+"){|f| f.write @password }

    Process.detach pid
  end


  ##
  # Stop a session.

  def end_session
    return unless @session_pid
    Process.kill 9, @session_pid rescue false
    FileUtils.rm_f [@password_file, @pid_file]
  end


  ##
  # Check if a session is active.

  def has_session?
    Process.kill(0, @session_pid) && @session_pid rescue false
  end


  ##
  # Get a password from either the password file or by prompting the
  # user if a password file is unavailable. Returns a sha1 of the password
  # passed as an arg.

  def get_password plain_password=nil
    password   = File.read @password_file if File.file? @password_file

    password ||=
      Digest::SHA1.hexdigest(plain_password || request_password("Yak Password"))

    password
  end


  ##
  # Prompt the user for a new password (replacing and old one).
  # Prompts for password confirmation as well.

  def new_password password=nil
    password ||= request_new_password "New Password"
    @password  = Digest::SHA1.hexdigest password if password
  end


  ##
  # Loads and decrypts the data file into the @data attribute.

  def connect_data
    @data = if File.file? @data_file
              data = ""
              File.open(@data_file, "rb"){|f| data << f.read }
              YAML.load decrypt(data)
            else
              {}
            end
  end


  ##
  # Remove a key/value pair.

  def remove name
    @data.delete(name)
  end


  ##
  # Retrieve a value for a given key.

  def retrieve name
    @data[name]
  end


  ##
  # Add a key/value pair. If no value is passed, will prompt the user for one.

  def store name, value=nil
    value ||= request_new_password "'#{name}' Password"
    @data[name] = value
  end


  ##
  # Decrypt a string with a given password.

  def decrypt string, password=@password
    @cipher.decrypt
    @cipher.key = password
    get_cypher_out string
  end


  ##
  # Encrypt a string with a given password.

  def encrypt string, password=@password
    @cipher.encrypt
    @cipher.key = password
    get_cypher_out string
  end


  ##
  # Encrypt and write the Yak data back to the data file.

  def write_data password=@password
    data = encrypt @data.to_yaml, password
    File.open(@data_file, "w+"){|f| f.write data}
  end


  private


  ##
  # Prompts for a new password (password and confirmation).
  # Doesn't prompt for confirmation if @confirm_prompt is false.

  def request_new_password req_str="Password"
    password = request_password "#{req_str}"

    password_confirm = if @confirm_prompt
      request_password "#{req_str} (confirm)"
    else
      password
    end

    if password != password_confirm
      $stderr << "Password and password confirmation did not match.\n"
    else
      password.chomp
    end
  end


  ##
  # Prompt the user for a password.

  def request_password req_str="Password"
    @input.ask("#{req_str}:"){|q| q.echo = false}
  end


  def get_cypher_out string
    out = @cipher.update string
    out << @cipher.final
    out
  end
end
