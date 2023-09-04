#!/usr/bin/env python
"""
RudeIRC
RudeIRC assumes conf.rude is available and configed properly:

Config Example:

[IRC]
nickname = Rudie
server = irc.libera.chat
auto_join_channels = #irish
nickserv_password = password
port = 6697
ssl_enabled = True
font_family = Hack
font_size = 10
sasl_enabled = False
sasl_username = Rudie
sasl_password = password

password can be replaced with your nicks password to auto-auth with nickserv.
to use ssl or not you can designate by port: no ssl: 6667 yes ssl: 6697
ssl_enabled = False needs port 6667
ssl_enabled = True needs port 6697(usually)
"""

# Import GUI
from main_gui import IRCClientGUI
from rude_client import IRCClient
from config_window import ConfigWindow
from list_window import ChannelListWindow
from shared_imports import *


def main():
    """The Main Function for the RudeChat IRC Client."""
    
    script_directory = os.path.dirname(os.path.abspath(__file__))
    
    config_file_path = os.path.join(script_directory, 'conf.rude')

    irc_client = IRCClient()
    irc_client.read_config(config_file_path)

    gui = IRCClientGUI(irc_client)
    gui.start()

if __name__ == '__main__':
    main()