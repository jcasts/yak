= Yak

http://github.com/yaksnrainbows/yak

== Description

Yak is a simple command line app to store and retrieve passwords securely
under a master password, and allows one password repository per system user.
Retrieved passwords get copied to the clipboard by default.


== Configuration

Config can be set in ~/.yakrc.

Session is the length of time in seconds that Yak will remember the
master password:
  :session : 30

If using sessions is not desired and you want to enter the
master password every time, set:
  :session : false

Always set the password by default, use:
  :password : plain_text_password

Turn off password confirmation prompts when a new password is entered:
  :confirm_prompt : false


== Usage

Yak will always prompt you for the master password unless a yak session is
present, or the :password option is set in ~/.yakrc.
Yak sessions get refreshed everytime yak is called.

Adding a new password:
  $ yak -a gmail
  # prompts user for gmail password to save

  $ yak -a gmail my_password
  # uses my_password as gmail password and overwrites old value

Retrieving a saved password:
  $ yak gmail
  # copies the gmail password to the clipboard

  $ yak -p gmail
  >> my_password
  # outputs gmail password to stdout

Removing a stored password:
  $ yak -r gmail
  # deletes gmail entry completely

Changing the master password:
  $ yak -n
  # prompts for old password first, then the new password

Listing keys:
  $ yak --list
  # returns all saved keys

  $ yak --list key
  # returns all keys matching /key/

  $ yak --list ^key$
  # returns unique key matching /^key$/
