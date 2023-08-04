RudeIRC
RudeIRC assumes conf.rude is available and configed properly:

Config Example:

[IRC]
nickname = Rudie
server = irc.libera.chat
auto_join_channels = Rudie,#irish (When auto-joining channels have a pseudo channel set as your own nick, this way you can receive DMs, but DM support is limited at this time.)
nickserv_password = password
port = 6697
ssl_enabled = True
font_family = Hack
font_size = 10

password can be replaced with your nicks password to auto-auth with nickserv.
to use ssl or not you can designate by port: no ssl: 6667 yes ssl: 6697
ssl_enabled = False needs port 6667
ssl_enabled = True needs port 6697(usually)
