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
# To set the path to the yak data file:
#   :data_file: /path/to/file

class Yak

  VERSION = "1.0.4"

  DEFAULT_CONFIG = {:session => 30}

  # Different versions of ruby have a different namespace for CipherError
  CIPHER_ERROR = OpenSSL::Cipher::CipherError rescue OpenSSL::CipherError

  ##
  # Run Yak with argv:
  #   Yak.run %w{key}
  #   Yak.run %w{--add key}
  #   ...

  def self.run argv=ARGV
    user = `whoami`.chomp

    check_user_setup user

    config = DEFAULT_CONFIG.merge load_config(user)

    options = parse_args argv

    yak = new user, config

    yak.connect_data
    yak.start_session

    args = [options[:action], yak, options[:key], options[:value]].compact

    self.send(*args)

  rescue CIPHER_ERROR => e
    $stderr << "Bad password.\n"
    exit 1
  end


  ##
  # Setup yak for first run if it hasn't been.

  def self.check_user_setup user
    user_config_file = yak_config_file user

    return if File.file? user_config_file

    hl = HighLine.new $stdin, $stderr
    hl.say "Thanks for installing Yak!"

    data_file_opts = []

    usrhome = File.expand_path "~#{user}/"
    dropbox = File.expand_path "~#{user}/Dropbox"

    data_file_opts << dropbox if File.directory? dropbox
    data_file_opts << usrhome if File.directory? usrhome

    data_path = hl.choose do |menu|
      menu.prompt = "Where would you like your data file to live?"
      menu.choices(*data_file_opts)
      menu.choice "other" do
        hl.ask "Enter path:"
      end
    end

    data_file  = File.join data_path, ".yakdata"
    new_config = DEFAULT_CONFIG.merge(:data_file => data_file)

    make_config_file user, new_config
  end


  ##
  # Load the ~/.yakrc file and return.

  def self.load_config user
    user_config_file = yak_config_file user

    YAML.load_file user_config_file
  end


  ##
  # Create a new user config file.

  def self.make_config_file user, new_config=DEFAULT_CONFIG
    user_config_file = yak_config_file user
    config_str = new_config.to_yaml

    File.open(user_config_file, "w+"){|f| f.write config_str }
    $stderr << "Created Yak config file #{user_config_file}:\n"
    $stderr << "#{config_str}\n"
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


  def self.print_password yak, name
    $stdout << "#{yak.retrieve(name)}\n"
  end


  def self.delete_data yak
    yak.delete_data_file! true
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
               when /darwin/ then "pbcopy"
               when /linux/  then "xclip"
               when /cygwin/ then "putclip"
               else
                 $stderr << "No clipboad cmd for platform #{RUBY_PLATFORM}\n"
                 exit 1
               end

    Session::Bash.new.execute "echo -n \"#{string}\ | #{copy_cmd}"
  end


  def self.yak_config_file user
    File.expand_path "~#{user}/.yakrc"
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

      opt.on('-p', '--print KEY',
             'Print the password for the given key to stdout') do |key|
        options[:action] = :print_password
        options[:key]    = key
      end

      opt.on('--delete-data',
             'Delete the data file - lose all saved info') do
        options[:action] = :delete_data
      end
    end

    opts.parse! argv

    options[:action] ||= :retrieve
    options[:key]    ||= argv.shift
    options[:value]  ||= argv.shift

    if options[:action] == :retrieve && options[:key].nil?
      $stderr << opts.to_s
      exit 1
    end

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

    @yak_dir = File.expand_path "~#{user}/.yak"
    FileUtils.mkdir @yak_dir unless File.directory? @yak_dir

    @pid_file      = File.join @yak_dir, "pid"
    @password_file = File.join @yak_dir, "password"
    @data_file     = options[:data_file] || File.join(@yak_dir, "data")

    @session_pid = nil
    @session_pid = File.read(@pid_file).to_i if File.file? @pid_file

    @password = nil

    @cipher = OpenSSL::Cipher::Cipher.new "aes-256-cbc"

    @session_length = options.has_key?(:session) ? options[:session] : 30
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
    File.open(@password_file, "w+"){|f| f.write sha_password }

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
  # Check if the data file exists.

  def data_file_exists?
    File.file? @data_file
  end


  ##
  # Deletes the user's data file forever!

  def delete_data_file! confirm=false
    confirmed = confirm ? @input.agree("Delete all passwords? (y/n)") : true
    FileUtils.rm_f(@data_file) if confirmed
  end


  ##
  # Get the SHA-encrypted password used for encoding data.

  def sha_password
    new_password unless data_file_exists?
    @password ||= get_password
  end


  ##
  # Get a password from either the password file or by prompting the
  # user if a password file is unavailable. Returns a sha1 of the password
  # passed as an arg.

  def get_password plain_pswd=nil
    password = File.read @password_file if File.file?(@password_file)

    plain_pswd ||= request_password "Master Password" if !password

    password ||= Digest::SHA1.hexdigest plain_pswd

    password
  end


  ##
  # Prompt the user for a new password (replacing and old one).
  # Prompts for password confirmation as well.

  def new_password password=nil
    password ||= request_new_password "Set New Master Password"
    @password  = Digest::SHA1.hexdigest password
  end


  ##
  # Loads and decrypts the data file into the @data attribute.

  def connect_data
    if data_file_exists?
      data = ""
      File.open(@data_file, "rb"){|f| data << f.read }
      @data = YAML.load decrypt(data)
    else
      @data = {}
      write_data
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

  def decrypt string, password=nil
    get_cypher_out :decrypt, string, password
  end


  ##
  # Encrypt a string with a given password.

  def encrypt string, password=nil
    get_cypher_out :encrypt, string, password
  end


  ##
  # Encrypt and write the Yak data back to the data file.

  def write_data password=nil
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


  def get_cypher_out method, string, password=nil
    password ||= sha_password

    @cipher.send method
    @cipher.key = password

    out = @cipher.update string
    out << @cipher.final
    out
  end
end
