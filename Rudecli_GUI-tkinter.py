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


# Python standard libraries
import configparser
import datetime
import fnmatch
import logging
import os
import platform
import random
import re
import socket
import ssl
import subprocess
import sys
import textwrap
import threading
import time
from functools import partial
from queue import Queue

# Third-party libraries
import irctokens
import tkinter as tk
from plyer import notification
from tkinter import messagebox, scrolledtext, Menu, ttk
import tkinter.font as tkFont

# Local application/library specific imports
from tkinter.constants import *

class IRCClient:
    MAX_MESSAGE_HISTORY_SIZE = 200

    def __init__(self):
        # Initialization method and related properties
        self.irc_client_gui = None
        self.decoder = irctokens.StatefulDecoder()
        self.encoder = irctokens.StatefulEncoder()
        self.message_queue = Queue()
        self.exit_event = threading.Event()

        # Data structures and storage properties
        self.channel_messages = {}
        self.joined_channels: list = []
        self.channel_list = []
        self.current_channel: str = ''
        self.user_list = {}
        self.temp_user_list = {}
        self.whois_data = {}
        self.dm_users = []
        self.dm_messages = {}
        self.user_dual_privileges = {}
        self.backup_nicknames = ["Rudie", "stixie"]
        self.ignore_list = []
        self.friend_list = []
        self.server_capabilities = {}
        self.load_ignore_list()
        self.load_friend_list()

        # Threading and synchronization related properties
        self.user_list_lock = threading.Lock()
        self.receive_thread = None
        self.stay_alive_thread = None
        self.reconnection_thread = None
        self.channel_list_window = None

        # Protocol specific properties
        self.current_nick_index = 0
        self.has_auto_joined = False
        self.sound_ctcp_count = 0
        self.sound_ctcp_limit = 5
        self.sound_ctcp_limit_flag = False
        self.show_channel_list_flag = False 

        # Other properties
        self.reset_timer = None

    def read_config(self, config_file):
        """
        Reads the config file
        """
        config = configparser.ConfigParser()
        config.read(config_file)

        self.server = config.get('IRC', 'server')
        self.port = config.getint('IRC', 'port')
        self.ssl_enabled = config.getboolean('IRC', 'ssl_enabled')
        self.nickname = config.get('IRC', 'nickname')
        self.nickserv_password = config.get('IRC', 'nickserv_password')
        self.auto_join_channels = config.get('IRC', 'auto_join_channels').split(',')

        # SASL configurations
        self.sasl_enabled = config.getboolean('IRC', 'sasl_enabled', fallback=False)
        self.sasl_username = config.get('IRC', 'sasl_username', fallback=self.nickname)
        self.sasl_password = config.get('IRC', 'sasl_password', fallback=self.nickserv_password)

    def connect(self):
        """
        Connect to the IRC server
        """

        # Get the directory of the current script
        script_directory = os.path.dirname(os.path.abspath(__file__))

        # Set absolute path for the Splash directory
        splash_dir = os.path.join(script_directory, 'Splash')
        splash_files = [f for f in os.listdir(splash_dir) if os.path.isfile(os.path.join(splash_dir, f))]
        selected_splash_file = random.choice(splash_files)

        # Read the selected ASCII art file
        with open(os.path.join(splash_dir, selected_splash_file), 'r', encoding='utf-8') as f:
            clover_art = f.read()

        print(f'Connecting to server: {self.server}:{self.port}')

        if self.ssl_enabled:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.irc = context.wrap_socket(socket.socket(socket.AF_INET6 if ':' in self.server else socket.AF_INET),
                                           server_hostname=self.server)
        else:
            self.irc = socket.socket(socket.AF_INET6 if ':' in self.server else socket.AF_INET)

        self.irc.connect((self.server, self.port))
        self.irc_client_gui.update_message_text(f'Connecting to server: {self.server}:{self.port}\n')

        if self.sasl_enabled:
            self.irc.send(bytes('CAP REQ :sasl\r\n', 'UTF-8'))

        self.irc.send(bytes(f'NICK {self.nickname}\r\n', 'UTF-8'))
        self.irc.send(bytes(f'USER {self.nickname} 0 * :{self.nickname}\r\n', 'UTF-8'))
        print(f'Connected to server: {self.server}:{self.port}')
        self.irc_client_gui.update_message_text(f'Connected to server: {self.server}:{self.port}\n')
        self.irc_client_gui.update_message_text(clover_art)

    def disconnect(self):
        """
        Disconnect from the IRC server and stop any related threads.
        """
        # Close the socket connection
        if hasattr(self, 'irc'):
            self.irc.close()

        # Stop the threads if they're running
        for thread in [self.receive_thread, self.stay_alive_thread, self.reconnection_thread]:
            if thread and thread.is_alive():
                thread.join(timeout=1)

        # Reset states or data structures
        self.joined_channels = []
        self.current_channel = ''
        self.channel_messages = {}
        self.temp_user_list = {}
        self.user_list = {}
        self.has_auto_joined = False
        print(f"Disconnected")
        self.irc_client_gui.update_message_text(f"Disconnected\r\n")

    def reconnect(self, server=None, port=None):
        """
        Reconnect to the IRC server.
        """
        if server:
            self.set_server(server, port)

        self.disconnect()
        time.sleep(1)
        # Start a new connection
        self.reconnection_thread = threading.Thread(target=self.start)
        self.reconnection_thread.daemon = True
        self.reconnection_thread.start()

    def set_server(self, server, port=None):
        self.server = server
        if port:
            self.port = port
    
    def is_thread_alive(self):
        return self.reconnection_thread.is_alive()

    def send_message(self, message):
        """
        Sends messages
        """
        # Generate timestamp
        timestamp = datetime.datetime.now().strftime('[%H:%M:%S] ')

        # Split the message into lines
        lines = message.split("\n")

        for line in lines:
            # Send each line to the server
            self.irc.send(bytes(f'{line}\r\n', 'UTF-8'))

            # Extract the target channel and actual message content from the line
            target_match = re.match(r'PRIVMSG (\S+) :(.+)', line)
            if not target_match:
                continue

            target_channel, message_content = target_match.groups()

            # Check if it's a CTCP ACTION and format accordingly
            if message_content.startswith("\x01ACTION ") and message_content.endswith("\x01"):
                action_content = message_content[8:-1]
                formatted_message = f"* {self.nickname} {action_content}"
            else:
                formatted_message = message_content 

            # Generate the actual content of the message, not the entire command
            message_data = (timestamp, self.nickname, formatted_message)

            # Handle channel messages
            self.channel_messages.setdefault(target_channel, []).append(message_data)
            if len(self.channel_messages[target_channel]) > self.MAX_MESSAGE_HISTORY_SIZE:
                self.channel_messages[target_channel] = self.channel_messages[target_channel][-self.MAX_MESSAGE_HISTORY_SIZE:]

            # Handle DMs
            if target_channel not in self.joined_channels:
                if formatted_message.startswith("* "):
                    sent_dm = f"{timestamp} {formatted_message}\n"
                else:
                    sent_dm = f"{timestamp} <{self.nickname}> {formatted_message}\n"
                self.dm_messages.setdefault(target_channel, []).append(sent_dm)

            # Log the message with the timestamp for display
            self.log_message(target_channel, self.nickname, formatted_message, is_sent=True)

    def send_ctcp_request(self, target, command, parameter=None):
        """
        Send a CTCP request to the specified target (user or channel).
        """
        message = f'\x01{command}'
        if parameter:
            message += f' {parameter}'
        message += '\x01'
        self.send_message(f'PRIVMSG {target} :{message}')

    def change_nickname(self, new_nickname):
        """
        Changes your nickname
        """
        self.send_message(f'NICK {new_nickname}')
        self.nickname = new_nickname
        self.irc_client_gui.update_message_text(f'Nickname changed to: {new_nickname}\n')

    def join_channel(self, channel):
        """
        Joins a channel
        """
        self.send_message(f'JOIN {channel}')
        self.joined_channels.append(channel)
        self.channel_messages[channel] = []
        self.user_list[channel] = []
        self.irc_client_gui.update_message_text(f'Joined channel: {channel}\r\n')
        time.sleep(1)

    def leave_channel(self, channel):
        """
        Leaves a channel
        """
        self.send_message(f'PART {channel}')
        if channel in self.joined_channels:
            self.joined_channels.remove(channel)
        if channel in self.channel_messages:
            del self.channel_messages[channel]
        if channel in self.user_list:
            del self.user_list[channel]
        if self.current_channel == channel:
            self.current_channel = ''
        self.irc_client_gui.update_joined_channels_list(channel)

    def keep_alive(self):
        """
        Periodically sends a PING request.
        """
        while not self.exit_event.is_set():
            time.sleep(195)
            param = self.server
            self.send_message(f'PING {param}')

    def ping_server(self, target=None):
        """
        Like the keep alive, this is used by the command parser to send a manual PING request
        """
        if target:
            param = target
        else:
            param = self.server
        self.send_message(f'PING {param}')

    def sync_user_list(self):
        """
        Syncs the user list via /users
        """
        self.user_list[self.current_channel] =[]
        self.send_message(f'NAMES {self.current_channel}')

    def strip_ansi_escape_sequences(self, text):
        # Strip ANSI escape sequences
        ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        cleaned_text = ansi_escape.sub('', text)

        # Strip IRC color codes
        irc_color = re.compile(r'\x03\d{1,2}(,\d{1,2})?')
        return irc_color.sub('', cleaned_text)

    def handle_incoming_message(self):
        """
        The main method which handles incoming server and chat messages. 
        """
        remaining_data = ""

        while not self.exit_event.is_set():
            try:
                if not hasattr(self, 'irc'):
                    print("Socket not initialized.")
                data = self.irc.recv(4096).decode('UTF-8', errors='ignore')
                data = self.strip_ansi_escape_sequences(data)
                if not data:
                    break

                #prepend any remaining_data from the previous iteration to the new data
                data = remaining_data + data

                received_messages = ""
                self.server_feedback_buffer = ""
                messages = data.split('\r\n')

                #if the last message is incomplete, store it in remaining_data
                if not data.endswith('\r\n'):
                    remaining_data = messages[-1]
                    messages = messages[:-1]
                else:
                    remaining_data = ""

                #process each complete message
                for raw_message in messages:
                    # Generate timestamp
                    timestamp = datetime.datetime.now().strftime('[%H:%M:%S] ')
                    # Skip empty lines or lines with only whitespace
                    raw_message = raw_message.strip()
                    if not raw_message:
                        continue

                    try:
                        tokens = irctokens.tokenise(raw_message)
                    except ValueError as e:
                        print(f"Error: {e}")
                        continue

                    if tokens.source is not None:
                        sender = tokens.hostmask.nickname
                    else:
                        sender = None
                    self.message_queue.put(raw_message)

                    match tokens.command:
                        case "PING":
                            self.handle_ping(tokens)
                        
                        case "ERROR":
                            self.server_feedback_buffer += raw_message + "\n"
                            self.irc_client_gui.update_server_feedback_text(raw_message)
                        
                        case "CAP":
                            self.handle_cap(tokens)

                        case "AUTHENTICATE":
                            self.handle_sasl_auth(tokens)

                        case "903":
                            self.handle_sasl_successful()

                        case "904":
                            self.handle_sasl_failed()

                        case "376" | "001":
                            self.handle_welcome_or_end_of_motd(raw_message)

                        case "NOTICE":
                            received_message = self.handle_notice(tokens, timestamp, sender)
                            if received_message:
                                received_messages += received_message

                        case "005":
                            self.handle_isupport(tokens)

                        case "353":
                            self.handle_353(tokens)

                        case "352" | "315":
                            self.handle_who_reply(tokens)

                        case "366":
                            self.handle_366(tokens)

                        case "311" | "312" | "313" | "317" | "319" | "301" | "671" | "338" | "318":
                            self.handle_whois_replies(tokens.command, tokens)
                        case "391":
                            self.handle_time_request(tokens)
                        case "433":
                            self.handle_nickname_conflict(tokens)

                        case "322":
                            self.handle_list_response(tokens)
                        case "323":
                            self.save_channel_list_to_file()

                        case "PART":
                            self.handle_part_command(tokens, raw_message)

                        case "JOIN":
                            self.handle_join_command(tokens, raw_message)

                        case "QUIT":
                            self.handle_quit_command(tokens, raw_message)

                        case "NICK":
                            old_nickname = tokens.hostmask.nickname
                            new_nickname = tokens.params[0]
                            self.handle_nick_change(old_nickname, new_nickname, channel, raw_message)

                        case "MODE":
                            channel = tokens.params[0]
                            mode = tokens.params[1]
                            if len(tokens.params) > 2:  # Ensure there's a target user for the mode change
                                target_user = tokens.params[2]
                                self.handle_mode_changes(channel, mode, target_user)
                            self.irc_client_gui.update_server_feedback_text(raw_message)
                        case "KICK":
                            self.handle_kick_event(tokens, raw_message)

                        case "PRIVMSG":
                            received_messages = self.handle_privmsg(tokens, timestamp)

                        case _:
                            self.handle_default_case(raw_message)

                    # limit the chat history size for each channel
                    for channel in self.channel_messages:
                        if len(self.channel_messages[channel]) > self.MAX_MESSAGE_HISTORY_SIZE:
                            self.channel_messages[channel] = self.channel_messages[channel][-self.MAX_MESSAGE_HISTORY_SIZE:]

            except OSError as e:
                if e.errno == 9:
                    print("Socket closed.")
                    break
                else:
                    print(f"Unexpected Error during data reception: {e}")

            if received_messages:
                self.message_queue.put(received_messages)
                self.irc_client_gui.update_message_text(received_messages)

    def handle_list_response(self, tokens):
        """
        Handle the individual channel data from the LIST command.
        """
        channel_name = tokens.params[1]
        visible_users = tokens.params[2]
        topic = tokens.params[3]

        channel_info = {
            "name": channel_name,
            "users": visible_users,
            "topic": topic
        }

        self.channel_list.append(channel_info)

    def handle_time_request(self, tokens):
        """
        Handle the server's response for the TIME command.
        """
        server_name = tokens.params[0]  # The server's name
        local_time = tokens.params[1]   # The local time on the server

        # Display the information in your client's GUI
        message = f"Server Time from {server_name}: {local_time}"
        self.irc_client_gui.update_message_text(message)

    def handle_ping(self, tokens):
        ping_param = tokens.params[0]
        pong_response = f'PONG {ping_param}'
        self.send_message(pong_response)

    def handle_cap(self, tokens):
        if "ACK" in tokens.params and "sasl" in tokens.params:
            self.send_message("AUTHENTICATE PLAIN")
        elif "NAK" in tokens.params:
            print("Server does not support SASL.")
            self.irc_client_gui.update_server_feedback_text("Error: Server does not support SASL.")
            self.send_message("CAP END")

    def handle_sasl_auth(self, tokens):
        if tokens.params[0] == "+":
            # Server is ready to receive authentication data.
            import base64
            auth_string = f"{self.sasl_username}\0{self.sasl_username}\0{self.sasl_password}"
            encoded_auth = base64.b64encode(auth_string.encode()).decode()
            self.send_message(f"AUTHENTICATE {encoded_auth}")

    def handle_sasl_successful(self):
        print("SASL authentication successful.")
        self.irc_client_gui.update_server_feedback_text("SASL authentication successful.")
        # End the capability negotiation after successful SASL authentication
        self.send_message("CAP END")

    def handle_sasl_failed(self):
        print("SASL authentication failed!")
        self.irc_client_gui.update_server_feedback_text("Error: SASL authentication failed!")
        # End the capability negotiation even if SASL authentication failed
        self.send_message("CAP END")

    def handle_welcome_or_end_of_motd(self, raw_message):
        self.irc_client_gui.update_server_feedback_text(raw_message)
        self.send_message(f'PRIVMSG NickServ :IDENTIFY {self.nickserv_password}')
        if not self.has_auto_joined:
            for channel in self.auto_join_channels:
                self.join_channel(channel)
            self.has_auto_joined = True

    def handle_notice(self, tokens, timestamp, sender):
        logging.debug(f"Received NOTICE from {sender} at {timestamp} with content: {tokens.params[1]}")

        target = tokens.params[0]
        notice_content = tokens.params[1]

        # Check if the target is a channel or the user
        if target.startswith(("#", "&", "+", "!")):
            logging.debug(f"NOTICE is channel-specific for channel {target}.")
            
            # This is a channel-specific NOTICE
            if target not in self.channel_messages:
                self.channel_messages[target] = []
            self.channel_messages[target].append((timestamp, sender, notice_content))
            if target == self.current_channel:
                logging.debug("Displaying NOTICE in current channel.")
                return f'{timestamp} [NOTICE] <{sender}> {notice_content}'
            else:
                self.notify_channel_activity(target)
                return None
        else:
            logging.debug("NOTICE is user-specific. Displaying in server/status tab.")
            
            # This is a user-specific NOTICE, display in a general "server" or "status" tab
            server_tab_content = f'[SERVER NOTICE] <{sender}> {notice_content}'
            self.irc_client_gui.update_server_feedback_text(server_tab_content)
            return None

    def handle_isupport(self, tokens):
        """
        Handle the RPL_ISUPPORT (005) server message.
        This method processes the server capabilities and updates the client's knowledge about them.
        """
        isupport_params = tokens.params[:-1]

        # Store these in a dictionary 
        new_capabilities = {}  # Track the new capabilities from this specific message
        for param in isupport_params:
            if '=' in param:
                key, value = param.split('=', 1)
                if key not in self.server_capabilities:  # Only display if it's a new capability
                    new_capabilities[key] = value
                    self.server_capabilities[key] = value
            else:
                # Some capabilities might just be flags without a value
                if param not in self.server_capabilities:
                    new_capabilities[param] = True
                    self.server_capabilities[param] = True

        # Display capabilities:
        for key, value in new_capabilities.items():
            display_text = f"{key}: {value}"
            self.irc_client_gui.update_server_feedback_text(display_text)

    def handle_353(self, tokens):
        if len(tokens.params) == 4:
            channel = tokens.params[2]
            users = tokens.params[3].split()
        elif len(tokens.params) == 3:
            channel = tokens.params[1]
            users = tokens.params[2].split()
        else:
            print("Error: Unexpected format for the 353 command.")
            return

        if channel not in self.temp_user_list:
            self.temp_user_list[channel] = []
        self.temp_user_list[channel].extend(users)  # Accumulate users in the temp list

    def handle_366(self, tokens):
        channel = tokens.params[1]
        
        with self.user_list_lock:
            if channel in self.temp_user_list:
                self.user_list[channel] = self.temp_user_list[channel]
                del self.temp_user_list[channel]
                self.irc_client_gui.update_joined_channels_list(channel)

    def handle_who_reply(self, tokens):
        """
        Handle the WHO reply from the server.
        """
        if not hasattr(self, 'who_details'):
            self.who_details = []

        if tokens.command == "352":  # Standard WHO reply
            # Parse the WHO reply
            channel = tokens.params[1]
            username = tokens.params[2]
            host = tokens.params[3]
            server = tokens.params[4]
            nickname = tokens.params[5]
            user_details = {
                "nickname": nickname,
                "username": username,
                "host": host,
                "server": server,
                "channel": channel
            }
            self.who_details.append(user_details)

        elif tokens.command == "315":  # End of WHO list
            messages = []
            for details in self.who_details:
                message = f"User {details['nickname']} ({details['username']}@{details['host']}) on {details['server']} in {details['channel']}\r\n"
                messages.append(message)
            final_message = "\n".join(messages)
            self.irc_client_gui.update_message_text(final_message)
            # Reset the who_details for future use
            self.who_details = []

    def handle_whois_replies(self, command, tokens):
        nickname = tokens.params[1]

        if command == "311":
            username = tokens.params[2]
            hostname = tokens.params[3]
            realname = tokens.params[5]
            self.whois_data[nickname] = {"Username": username, "Hostname": hostname, "Realname": realname}

        elif command == "312":
            server_info = tokens.params[2]
            if self.whois_data.get(nickname):
                self.whois_data[nickname]["Server"] = server_info

        elif command == "313":
            operator_info = tokens.params[2]
            if self.whois_data.get(nickname):
                self.whois_data[nickname]["Operator"] = operator_info

        elif command == "317":
            idle_time_seconds = int(tokens.params[2])
            idle_time = str(datetime.timedelta(seconds=idle_time_seconds))
            if self.whois_data.get(nickname):
                self.whois_data[nickname]["Idle Time"] = idle_time

        elif command == "319":
            channels = tokens.params[2]
            self.whois_data[nickname]["Channels"] = channels

        elif command == "301":
            away_message = tokens.params[2]
            if nickname not in self.whois_data:
                self.whois_data[nickname] = {}  
            self.whois_data[nickname]["Away"] = away_message

        elif command == "671":
            secure_message = tokens.params[2]
            self.whois_data[nickname]["Secure Connection"] = secure_message

        elif command == "338":
            ip_address = tokens.params[2]
            self.whois_data[nickname]["Actual IP"] = ip_address

        elif command == "318":
            if self.whois_data.get(nickname):
                whois_response = f"WHOIS for {nickname}:\n"
                for key, value in self.whois_data[nickname].items():
                    whois_response += f"{key}: {value}\n"

                # Generate and append the /ignore suggestion
                ignore_suggestion = f"*!{self.whois_data[nickname]['Username']}@{self.whois_data[nickname]['Hostname']}"
                whois_response += f"\nSuggested /ignore mask: {ignore_suggestion}\n"

                self.irc_client_gui.update_message_text(whois_response)

    def handle_nickname_conflict(self, tokens):
        if tokens.params and len(tokens.params) > 1:
            taken_nickname = tokens.params[1]
            error_message = tokens.params[2]
            msg = f"Error: The nickname {taken_nickname} is already in use. Reason: {error_message}"
            self.irc_client_gui.update_server_feedback_text(msg)

            # Try the next nickname in the backup list
            if self.current_nick_index < len(self.backup_nicknames):
                new_nickname = self.backup_nicknames[self.current_nick_index]
                self.current_nick_index += 1
                self.change_nickname(new_nickname)
                feedback = f"Attempting to use nickname: {new_nickname}"
                self.irc_client_gui.update_server_feedback_text(feedback)
            else:
                feedback = "All backup nicknames are exhausted. Please set a new nickname."
                self.irc_client_gui.update_server_feedback_text(feedback)

    def handle_part_command(self, tokens, raw_message):
        if tokens.source is not None:
            quit_user = tokens.hostmask.nickname
            quit_user = self.strip_nick_prefix(quit_user)
            channel = tokens.params[0]

            with self.user_list_lock:
                if channel in self.user_list:
                    similar_users = [user for user in self.user_list[channel] 
                                     if user == quit_user or 
                                     user.startswith('@' + quit_user) or 
                                     user.startswith('+' + quit_user)]
                    for user in similar_users:
                        self.user_list[channel].remove(user)
                    # Only update the GUI if the affected channel is the current channel
                    if channel == self.irc_client_gui.current_channel:
                        self.irc_client_gui.update_user_list(channel)

        self.server_feedback_buffer += raw_message + "\n"
        self.irc_client_gui.update_server_feedback_text(raw_message)

    def handle_join_command(self, tokens, raw_message):
        if tokens.source is not None:
            join_user = tokens.hostmask.nickname
            channel = tokens.params[0]

            if join_user in self.friend_list:
                self.friend_online(channel, join_user)

            with self.user_list_lock:
                if channel in self.user_list:
                    if join_user not in self.user_list[channel]:
                        self.user_list[channel].append(join_user)
                    else:
                        self.user_list[channel].remove(join_user)
                        self.user_list[channel].append(join_user) 
                    # Only update the GUI if the affected channel is the current channel
                    if channel == self.irc_client_gui.current_channel:
                        self.irc_client_gui.update_user_list(channel)
                else:
                    self.user_list[channel] = [join_user]
                    # Only update the GUI if the affected channel is the current channel
                    if channel == self.irc_client_gui.current_channel:
                        self.irc_client_gui.update_user_list(channel)

        self.server_feedback_buffer += raw_message + "\n"
        self.irc_client_gui.update_server_feedback_text(raw_message)

    def handle_quit_command(self, tokens, raw_message):
        if tokens.source is not None:
            quit_user = tokens.hostmask.nickname

            with self.user_list_lock:
                for channel in self.user_list:
                    similar_users = [user for user in self.user_list[channel] 
                                     if user == quit_user or 
                                     user.startswith('@' + quit_user) or 
                                     user.startswith('+' + quit_user)]
                    for user in similar_users:
                        self.user_list[channel].remove(user)
                    # Only update the GUI if the affected channel is the current channel
                    if channel == self.irc_client_gui.current_channel:
                        self.irc_client_gui.update_user_list(channel)

        self.server_feedback_buffer += raw_message + "\n"
        self.irc_client_gui.update_server_feedback_text(raw_message)

    def handle_nick_change(self, old_nickname, new_nickname, channel, raw_message):
        # Display the nick change message in the chat window
        nick_change_message_content = f"{old_nickname} has changed their nickname to {new_nickname}"
        self.irc_client_gui.display_message_in_chat(nick_change_message_content)
        
        # Update internal user lists to reflect the nickname change
        with self.user_list_lock:
            for chan, users in self.user_list.items():
                if old_nickname in users:
                    users.remove(old_nickname)
                    users.append(new_nickname)
                elif "@" + old_nickname in users:
                    users.remove("@" + old_nickname)
                    users.append("@" + new_nickname)
                elif "+" + old_nickname in users:
                    users.remove("+" + old_nickname)
                    users.append("+" + new_nickname)
        
        if channel == self.irc_client_gui.current_channel:
            self.irc_client_gui.update_user_list(channel)
            
        self.irc_client_gui.update_server_feedback_text(raw_message)

    def handle_kick_event(self, tokens, raw_message):
        """
        Handle the KICK event from the server.
        """
        channel = tokens.params[0]
        kicked_nickname = tokens.params[1]
        reason = tokens.params[2] if len(tokens.params) > 2 else 'No reason provided'
        
        # Display the kick message in the chat window
        kick_message_content = f"{kicked_nickname} has been kicked from {channel} by {tokens.hostmask.nickname} ({reason})"
        self.irc_client_gui.display_message_in_chat(kick_message_content)

        # Update internal user lists to reflect the kick
        with self.user_list_lock:
            if channel in self.user_list:
                if kicked_nickname in self.user_list[channel]:
                    self.user_list[channel].remove(kicked_nickname)
                elif "@" + kicked_nickname in self.user_list[channel]:
                    self.user_list[channel].remove("@" + kicked_nickname)
                elif "+" + kicked_nickname in self.user_list[channel]:
                    self.user_list[channel].remove("+" + kicked_nickname)

        # Update the GUI user list if the kick happened in the current channel
        if channel == self.irc_client_gui.current_channel:
            self.irc_client_gui.update_user_list(channel)

        # Update server feedback
        self.irc_client_gui.update_server_feedback_text(raw_message)

    def should_ignore_message(self, hostmask, sender):
        """Determine if a message should be ignored."""
        return self.should_ignore(hostmask) or sender in self.ignore_list

    def format_received_message(self, message_content, sender):
        """Format the received message."""
        if message_content.startswith("\x01ACTION ") and message_content.endswith("\x01"):
            action_content = message_content[8:-1]
            return f"* {sender} {action_content}"
        return message_content

    def handle_dm(self, sender, formatted_message, timestamp):
        """Handle Direct Messages (DMs)."""
        if sender not in self.dm_users:
            self.dm_users.append(sender)
        if formatted_message.startswith('* '):
            received_dm = f"{timestamp} {formatted_message}\n"
        else:
            received_dm = f"{timestamp} <{sender}> {formatted_message}\n"
        self.log_message(f"{sender}", sender, formatted_message)
        if sender not in self.dm_messages:
            self.dm_messages[sender] = []
        self.dm_messages[sender].append(received_dm)

        # Check if this DM is already in the channels_with_activity list
        dm_name = f"DM: {sender}"
        if dm_name not in self.irc_client_gui.channels_with_activity:
            self.irc_client_gui.channels_with_activity.append(dm_name)
        self.irc_client_gui.update_joined_channels_list(dm_name)

        # Only display the DM in the GUI if the currently selected channel is the DM from this sender
        if self.current_channel == sender:
            self.irc_client_gui.update_message_text(received_dm, sender=sender, is_dm=True)

        # Handling CTCP requests here, inside the DM section
        if formatted_message.startswith("\x01") and formatted_message.endswith("\x01"):
            received_message = self.handle_ctcp_request(sender, formatted_message)
            if received_message:
                if sender not in self.dm_messages:
                    self.dm_messages[sender] = []
                self.dm_messages[sender].append((timestamp, received_message))

    def handle_channel_message(self, target, sender, formatted_message, timestamp):
        """Handle channel messages."""
        self.log_message(target, sender, formatted_message, is_sent=False)
        
        # Prepare the formatted message for display
        if formatted_message.startswith("* "):
            # For ACTION messages
            display_message = f'{timestamp} {formatted_message}\n'
        else:
            # For regular messages
            display_message = f'{timestamp} <{sender}> {formatted_message}\n'
        
        # Update the GUI if the message's channel is the current channel
        if self.irc_client_gui.current_channel == target:
            self.irc_client_gui.update_message_text(display_message)

        if sender == self.nickname:
            return

        if self.nickname in formatted_message:
            self.trigger_beep_notification(channel_name=target, message_content=formatted_message)
            if target not in self.irc_client_gui.channels_with_mentions:
                self.irc_client_gui.channels_with_mentions.append(target)
                self.irc_client_gui.update_joined_channels_list(target)

        if target not in self.irc_client_gui.channels_with_activity:
            self.irc_client_gui.channels_with_activity.append(target)
            self.irc_client_gui.update_joined_channels_list(target)

        if target not in self.channel_messages:
            self.channel_messages[target] = []

        self.channel_messages[target].append((timestamp, sender, formatted_message))

    def handle_privmsg(self, tokens, timestamp):
        """Main function to handle private messages."""
        target = tokens.params[0]
        message_content = tokens.params[1]

        # Constructing the hostmask from the given token attributes
        hostmask = f"{tokens.hostmask.nickname}!{tokens.hostmask.username}@{tokens.hostmask.hostname}"
        sender = tokens.hostmask.nickname  # Define the sender here

        # Check if the message should be ignored
        if self.should_ignore_message(hostmask, sender):
            return

        # Format the message content
        formatted_message = self.format_received_message(message_content, sender)

        if target == self.nickname:
            # This is a DM
            self.handle_dm(sender, formatted_message, timestamp)
        else:
            # This is a channel message
            self.handle_channel_message(target, sender, formatted_message, timestamp)

    def handle_default_case(self, raw_message):
        if raw_message.startswith(':'):
            # move message starting with ":" to server feedback
            self.server_feedback_buffer += raw_message + "\n"
            self.irc_client_gui.update_server_feedback_text(raw_message)
        else:
            # print other messages in the main chat window
            self.irc_client_gui.update_message_text(raw_message)

    def handle_ctcp_request(self, sender, message_content):
        # List of available CTCP commands
        available_ctcp_commands = ["VERSION", "CTCP", "TIME", "PING", "FINGER", "CLIENTINFO", "SOUND", "MOO"]

        # Split the CTCP message content at the first space to separate the command from any data
        ctcp_parts = message_content[1:-1].split(" ", 1)
        ctcp_command = ctcp_parts[0]

        # Check if the CTCP request has more than one command
        if ' ' in ctcp_parts[-1]:  # Checking if there's another space in the last part
            print(f"Ignoring CTCP request with multiple commands from {sender}.")
            return None

        # Check if the CTCP command is available
        if ctcp_command not in available_ctcp_commands:
            print(f"Ignoring unavailable CTCP command '{ctcp_command}' from {sender}.")
            return None

        if ctcp_command == "VERSION":
            # Respond to VERSION request
            version_reply = "\x01VERSION IRishC v2.6-3\x01"
            self.send_message(f'NOTICE {sender} :{version_reply}')

        elif ctcp_command == "CTCP":
            # Respond to CTCP request
            ctcp_response = "\x01CTCP response\x01"
            self.send_message(f'NOTICE {sender} :{ctcp_response}')

        elif ctcp_command == "TIME":
            import pytz
            dublin_tz = pytz.timezone('Europe/Dublin')
            dublin_time = datetime.datetime.now(dublin_tz).strftime("%Y-%m-%d %H:%M:%S")
            time_reply = "\x01TIME " + dublin_time + "\x01"
            self.send_message(f'NOTICE {sender} :{time_reply}')

        elif ctcp_command == "PING":
            if len(ctcp_parts) > 1:
                ping_data = ctcp_parts[1]
                ping_reply = "\x01PING " + ping_data + "\x01"
                self.send_message(f'NOTICE {sender} :{ping_reply}')
            else:
                print("Received PING CTCP request without timestamp/data.")

        elif ctcp_command == "FINGER":
            # Respond to FINGER request (customize as per requirement)
            version_data = "IRishC v2.7"
            finger_reply = f"\x01FINGER User: {self.nickname}, {self.server}, {version_data}\x01"
            self.send_message(f'NOTICE {sender} :{finger_reply}')

        elif ctcp_command == "CLIENTINFO":
            # Respond with supported CTCP commands
            client_info_reply = "\x01CLIENTINFO VERSION CTCP TIME PING FINGER SOUND\x01"
            self.send_message(f'NOTICE {sender} :{client_info_reply}')

        elif ctcp_command == "SOUND":
            if self.sound_ctcp_count < self.sound_ctcp_limit:
                # Increment the counter
                self.sound_ctcp_count += 1
                # SOUND CTCP can include a file or description of the sound. This is just for logging.
                sound_data = ctcp_parts[1] if len(ctcp_parts) > 1 else "Unknown sound"
                self.trigger_beep_notification()
            else:
                print("SOUND CTCP limit reached. Ignoring...")
                if not self.sound_ctcp_limit_flag:  # If the flag isn't set yet
                    self.sound_ctcp_limit_flag = True
                    self.start_reset_timer()

        elif ctcp_command == "MOO":
            moo_reply = "MOO!"
            version_data = "IRishC v2.7"
            cow_hello = "Hi Cow!"
            self.send_message(f'NOTICE {sender} :{moo_reply}, {version_data}, {cow_hello}')

        else:
            if message_content.startswith("\x01ACTION") and message_content.endswith("\x01"):
                action_content = message_content[8:-1]
                action_message = f"* {sender} {action_content}"
                self.log_message(self.current_channel, sender, action_message, is_sent=False)
                return action_message
            else:
                self.log_message(self.current_channel, sender, message_content, is_sent=False)
                return f'<{sender}> {message_content}'
        return None  # No standard message to display

    def start_reset_timer(self):
        # If the flag isn't set, don't start the timer
        if not self.sound_ctcp_limit_flag:
            return

        # If a timer already exists, cancel it to avoid overlapping timers
        if self.reset_timer:
            self.reset_timer.cancel()

        # Set up the timer to call reset_counter after 15 minutes (900 seconds)
        self.reset_timer = threading.Timer(900, self.reset_counter)
        self.reset_timer.daemon = True
        self.reset_timer.start()

    def reset_counter(self):
        print("Resetting SOUND CTCP counter...")
        self.sound_ctcp_count = 0
        self.sound_ctcp_limit_flag = False

    def handle_mode_changes(self, channel, mode, user):
        if mode == "+o":
            #if user already has voice (+v), upgrade to operator
            if "+" + user in self.user_list[channel]:
                self.user_list[channel].remove("+" + user)
                self.user_list[channel].append("@" + user)
                self.user_dual_privileges[user] = True
            #else if user is already in list without voice, just add operator status
            elif user in self.user_list[channel]:
                self.user_list[channel].remove(user)
                self.user_list[channel].append("@" + user)
        elif mode == "-o":
            #if the user is an operator
            if "@" + user in self.user_list[channel]:
                self.user_list[channel].remove("@" + user)
                # If they were given voice while being an operator, they should retain voice after de-op
                if self.user_dual_privileges.get(user):
                    self.user_list[channel].append("+" + user)
                # If they were not given voice while being an operator, revert to normal user status
                else:
                    self.user_list[channel].append(user)
                # If the user was tracked for dual privileges, remove them from that tracking
                if user in self.user_dual_privileges:
                    del self.user_dual_privileges[user]
        elif mode == "+v":
            # Give voice mode only if they are not an operator; if they are, mark them for dual privileges
            if user in self.user_list[channel] and "@" + user not in self.user_list[channel]:
                self.user_list[channel].remove(user)
                self.user_list[channel].append("+" + user)
            elif "@" + user in self.user_list[channel]:
                self.user_dual_privileges[user] = True
        elif mode == "-v":
            # Take voice mode
            if "+" + user in self.user_list[channel]:
                self.user_list[channel].remove("+" + user)
                self.user_list[channel].append(user)
        if channel == self.irc_client_gui.current_channel:
            self.irc_client_gui.update_user_list(channel)

    def trigger_beep_notification(self, channel_name=None, message_content=None):
        """
        You've been pinged! Plays a beep or noise on mention.
        """
        script_directory = os.path.dirname(os.path.abspath(__file__))
        
        if sys.platform.startswith("linux"):
            # Linux-specific notification sound using paplay
            sound_path = os.path.join(script_directory, "Sounds", "Notification4.wav")
            os.system(f"paplay {sound_path}")
        elif sys.platform == "darwin":
            # macOS-specific notification sound using afplay
            os.system("afplay /System/Library/Sounds/Ping.aiff")
        elif sys.platform == "win32":
            # Windows-specific notification using winsound
            import winsound
            duration = 75  # milliseconds
            frequency = 1200  # Hz
            winsound.Beep(frequency, duration)
        else:
            # For other platforms, print a message
            print("Beep notification not supported on this platform.")

        try:
            self.irc_client_gui.trigger_desktop_notification(channel_name, message_content=message_content)
        except Exception as e:
            print(f"Error triggering desktop notification: {e}")

    def sanitize_channel_name(self, channel):
        #gotta remove any characters that are not alphanumeric or allowed special characters
        return re.sub(r'[^\w\-\[\]{}^`|]', '_', channel)

    def log_message(self, channel, sender, message, is_sent=False):
        """
        Logs your chats for later use
        """
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Split the message into lines
        lines = message.split("\n")
        
        # Detect if the message is an action message
        is_action = lines[0].startswith('* ')
        
        # Construct the log line
        if is_sent:
            if is_action:
                log_line = f'[{timestamp}] {lines[0]}\n'
            else:
                log_line = f'[{timestamp}] <{self.nickname}> {lines[0]}\n'
        else:
            if is_action:
                log_line = f'[{timestamp}] {lines[0]}\n'
            else:
                log_line = f'[{timestamp}] <{sender}> {lines[0]}\n'
        
        # Add the subsequent lines without timestamp
        for line in lines[1:]:
            if is_action:
                log_line += f'           {line}\n'
            else:
                log_line += f'           <{sender if is_sent else self.nickname}> {line}\n'
        
        # Get the directory of the current script
        script_directory = os.path.dirname(os.path.abspath(__file__))

        # Construct the full path for the Logs directory
        logs_directory = os.path.join(script_directory, 'Logs')
        
        # Create the Logs directory if it doesn't exist
        os.makedirs(logs_directory, exist_ok=True)

        # Construct the full path for the log file inside the Logs directory
        filename = os.path.join(logs_directory, f'irc_log_{self.sanitize_channel_name(channel)}.txt')

        with open(filename, 'a', encoding='utf-8') as file:
            file.write(log_line)

    def save_friend_list(self):
        """
        save Friend list!
        """
        
        # Get the directory of the current script
        script_directory = os.path.dirname(os.path.abspath(__file__))

        # Construct the full path for the friend_list.txt
        file_path = os.path.join(script_directory, 'friend_list.txt')

        with open(file_path, "w", encoding='utf-8') as f:
            for user in self.friend_list:
                f.write(f"{user}\n")

    def load_friend_list(self):
        """
        load Friend list!
        """
        
        # Get the directory of the current script
        script_directory = os.path.dirname(os.path.abspath(__file__))

        # Construct the full path for the friend_list.txt
        file_path = os.path.join(script_directory, 'friend_list.txt')

        if os.path.exists(file_path):
            with open(file_path, "r", encoding='utf-8') as f:
                self.friend_list = [line.strip() for line in f.readlines()]

    def save_ignore_list(self):
        """
        saves ignore list
        """
        
        # Get the directory of the current script
        script_directory = os.path.dirname(os.path.abspath(__file__))

        # Construct the full path for the ignore_list.txt
        file_path = os.path.join(script_directory, 'ignore_list.txt')

        with open(file_path, "w", encoding='utf-8') as f:
            for item in self.ignore_list:
                f.write(f"{item}\n")

    def load_ignore_list(self):
        """
        loads ignore list
        """
        
        # Get the directory of the current script
        script_directory = os.path.dirname(os.path.abspath(__file__))

        # Construct the full path for the ignore_list.txt
        file_path = os.path.join(script_directory, 'ignore_list.txt')

        if os.path.exists(file_path):
            with open(file_path, "r", encoding='utf-8') as f:
                self.ignore_list = [line.strip() for line in f.readlines()]
            
    def reload_ignore_list(self):
        self.ignore_list = []
        self.load_ignore_list()
        self.irc_client_gui.update_message_text(f"Ignore List reloaded C:<\r\n")
        for person in self.ignore_list:
            self.irc_client_gui.update_message_text(f"{person}\r\n")

    def save_channel_list_to_file(self):
        """
        Save the channel list data to a file.
        """
        script_directory = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_directory, 'channel_list.txt')
        
        with open(file_path, 'w', encoding='utf-8') as f:
            for channel in self.channel_list:
                f.write(f"Channel: {channel['name']}, Users: {channel['users']}, Topic: {channel['topic']}\n")
        
        # Clear the channel list after saving
        self.channel_list.clear()
        self.show_channel_list_flag = True

        if self.show_channel_list_flag:
            self.display_channel_list_window()

    def should_ignore(self, hostmask):
        """
        This should ignore by hostmask but it doesn't work yet.
        """
        for pattern in self.ignore_list:
            if fnmatch.fnmatch(hostmask.lower(), pattern.lower()):
                return True
        return False

    def strip_nick_prefix(self, nickname):
        # Strip '@' or '+' prefix from the nickname if present
        if nickname.startswith('@') or nickname.startswith('+'):
            return nickname[1:]
        return nickname

    def notify_channel_activity(self, channel):
        """
        Channel Activity notification - old
        """
        self.irc_client_gui.update_server_feedback_text(f'Activity in channel {channel}!\r')

    def friend_online(self, channel, username):
        """
        Friend list!
        """
        self.irc_client_gui.update_message_text(f"{channel}: {username} is Online!\r\n")

    def whois(self, target):
        """
        Who is this? Sends a whois request
        """
        self.send_message(f'WHOIS {target}')

    def display_channel_list_window(self):
        script_directory = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_directory, 'channel_list.txt')
        
        # Check if the window is already open
        if self.channel_list_window and not self.channel_list_window.is_destroyed:
            # Bring the existing window to the front
            self.channel_list_window.lift()
        else:
            # Create a new window
            self.channel_list_window = ChannelListWindow(file_path)

    def start(self):
        while not self.exit_event.is_set():
            self.connect()
            self.receive_thread = threading.Thread(target=self.handle_incoming_message)
            self.receive_thread.daemon = True
            self.receive_thread.start()

            self.stay_alive_thread = threading.Thread(target=self.keep_alive)
            self.stay_alive_thread.daemon = True
            self.stay_alive_thread.start()

            self.gui_handler()
            self.exit_event.set()

    def gui_handler(self):
        """
        Passes messages from the logic to the GUI.
        """
        while True:
            raw_message = self.message_queue.get()


class IRCClientGUI:
    def __init__(self, irc_client):
        # Initialize attributes
        self.init_attributes(irc_client)
        
        # Set up the main GUI window
        self.setup_main_window()
        
        # Configure fonts and other styles
        self.configure_styles()
        
        # Set up the menu
        self.setup_menu()
        
        # Create and configure GUI widgets
        self.create_widgets()
        
        # Set up layout
        self.setup_layout()
        
        # Bind events
        self.bind_events()
        
        # Start threads
        self.start_threads()

    def init_attributes(self, irc_client):
        script_directory = os.path.dirname(os.path.abspath(__file__))
        self.irc_client = irc_client
        self.exit_event = irc_client.exit_event
        self.channels_with_mentions = []
        self.channels_with_activity = []
        self.input_history = []
        self.nickname_colors = {}
        self.current_channel = None
        self.ASCII_ART_DIRECTORY = os.path.join(script_directory, 'Art')
        self.ASCII_ART_MACROS = self.load_ascii_art_macros()
        self.current_config = self.load_config()
        self.selected_channel = None
        self.history_position = -1  
        self.MAX_HISTORY = 8  

    def setup_main_window(self):
        """Set up the main window of the GUI."""
        # Get the directory of the current script
        script_directory = os.path.dirname(os.path.abspath(__file__))

        self.root = tk.Tk()
        self.root.title("RudeChat")
        self.root.geometry("1200x800")

        # Platform-specific icon setting
        if platform.system() == "Windows":
            icon_path = os.path.join(script_directory, "rude.ico")
            self.root.iconbitmap(True, icon_path)
        else:
            icon_path = os.path.join(script_directory, "rude.png")
            self.icon_image = tk.PhotoImage(file=icon_path)
            self.root.iconphoto(True, self.icon_image)
            
    def configure_styles(self):
        default_font = self.current_config.get("font_family", "Hack")
        default_size = int(self.current_config.get("font_size", 10))
        self.chat_font = tkFont.Font(family=default_font, size=default_size)
        self.channel_user_list_font = tkFont.Font(family="Hack", size=9)
        self.server_font = tkFont.Font(family="Hack", size=9)

    def setup_menu(self):
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        self.settings_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Settings", menu=self.settings_menu)
        self.settings_menu.add_command(label="Configure", command=self.open_config_window)
        self.settings_menu.add_command(label="Reload Macros", command=self.reload_ascii_macros)
        self.settings_menu.add_command(label="Reload Ignore List", command=self.irc_client.reload_ignore_list)
        self.settings_menu.add_command(label="Reset Nick Color", command=self.reset_nick_colors)
        self.settings_menu.add_command(label="Help", command=self.display_help)

    def create_widgets(self):
        self.server_feedback_text = scrolledtext.ScrolledText(self.root, state=tk.DISABLED, bg="black", fg="#ff0000", height=5, font=self.server_font)
        current_font = self.server_feedback_text.cget("font")
        self.server_feedback_text.tag_configure("bold", font=(current_font, 10, "bold")) 
        self.server_feedback_text.tag_configure("italic", font=(current_font, 10, "italic"))
        self.server_feedback_text.tag_configure("bold_italic", font=(current_font, 10, "bold italic"))
        self.server_feedback_text.tag_configure("server_feedback", foreground="#7882ff")
        self.bold_font = ("Hack", 10, "bold")
        self.italic_font = ("Hack", 10, "italic")
        self.bold_italic_font = ("Hack", 10, "bold italic") 

        self.paned_window = tk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.message_frame = tk.Frame(self.paned_window, bg="black")
        self.message_text = scrolledtext.ScrolledText(self.message_frame, state=tk.DISABLED, bg="black", fg="#C0FFEE", cursor="arrow", font=self.chat_font)
        self.user_list_frame = tk.Frame(self.paned_window, width=20, height=400, bg="black")
        self.user_list_label = tk.Label(self.user_list_frame, text="Users:", bg="black", fg="#39ff14")
        self.user_list_text = scrolledtext.ScrolledText(self.user_list_frame, width=5, height=20, bg="black", fg="#39ff14", cursor="arrow", font=self.channel_user_list_font)
        self.joined_channels_label = tk.Label(self.user_list_frame, text="Channels:", bg="black", fg="#00bfff")
        self.joined_channels_text = scrolledtext.ScrolledText(self.user_list_frame, width=5, height=20, bg="black", fg="#ffffff", cursor="arrow", font=self.channel_user_list_font)
        self.input_frame = tk.Frame(self.root)
        self.nickname_label = tk.Label(self.input_frame, font=("Hack", 9, "italic"), text=f" $ {self.irc_client.nickname} #> ")
        self.input_entry = tk.Entry(self.input_frame)
        self.exit_button = tk.Button(self.input_frame, text="Exit", command=self.handle_exit)
        self.init_input_menu()
        self.init_message_menu()
        self.init_server_menu()
        self.init_user_menu()
        self.init_channel_menu()

    def setup_layout(self):
        self.server_feedback_text.grid(row=1, column=0, sticky="nsew", padx=1, pady=1)
        self.paned_window.grid(row=0, column=0, sticky="nsew", padx=1, pady=1)
        self.paned_window.add(self.message_frame)
        self.message_text.pack(fill=tk.BOTH, expand=True)
        self.paned_window.add(self.user_list_frame)
        self.user_list_label.pack()
        self.user_list_text.pack(fill=tk.BOTH, expand=True)
        self.joined_channels_label.pack()
        self.joined_channels_text.pack(fill=tk.BOTH, expand=True)
        self.input_frame.grid(row=2, column=0, sticky="ew", padx=1, pady=1)
        self.nickname_label.pack(side=tk.LEFT)
        self.input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.exit_button.pack(side=tk.RIGHT)
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=0) 
        self.root.grid_columnconfigure(0, weight=1)

    def bind_events(self):
        self.input_entry.bind("<Return>", self.handle_input)
        self.input_entry.bind("<Tab>", self.handle_tab_complete)
        self.input_entry.bind('<Up>', self.navigate_history)
        self.input_entry.bind('<Down>', self.navigate_history)
        self.joined_channels_text.bind("<Button-1>", self.switch_channel)
        self.joined_channels_text.bind("<B1-Motion>", lambda event: "break")
        self.joined_channels_text.bind("<ButtonRelease-1>", lambda event: "break")
        self.root.bind("<Configure>", self.delayed_sash_position)
        self.last_width = self.root.winfo_width()

    def start_threads(self):
        self.client_start_thread = threading.Thread(target=self.irc_client.start)
        self.client_start_thread.daemon = True 
        self.client_start_thread.start()
        self.irc_client.irc_client_gui = self

    def delayed_sash_position(self, event):
        # Cancel any previous delayed adjustments
        if hasattr(self, "sash_adjustment_id"):
            self.root.after_cancel(self.sash_adjustment_id)
        # Schedule a new adjustment 100ms in the future
        self.sash_adjustment_id = self.root.after(20, self.adjust_sash_position)

    def adjust_sash_position(self):
        new_width = self.root.winfo_width()
        if new_width != self.last_width:
            self.paned_window.sash_place(0, new_width - 170, 0)
            self.last_width = new_width

    def init_input_menu(self):
        """
        Right click menu.
        """
        self.input_menu = Menu(self.input_entry, tearoff=0)
        self.input_menu.add_command(label="Cut", command=self.cut_text)
        self.input_menu.add_command(label="Copy", command=self.copy_text)
        self.input_menu.add_command(label="Paste", command=self.paste_text)
        self.input_menu.add_command(label="Select All", command=self.select_all_text)

        self.input_entry.bind("<Button-3>", self.show_input_menu)

    def init_message_menu(self):
        """
        Right click menu for the main chat window.
        """
        self.message_menu = Menu(self.message_text, tearoff=0)
        self.message_menu.add_command(label="Copy", command=self.copy_text_message)
        
        self.message_text.bind("<Button-3>", self.show_message_menu)

    def init_server_menu(self):
        """
        Right click menu for the server window.
        """
        self.server_menu = Menu(self.server_feedback_text, tearoff=0)
        self.server_menu.add_command(label="Copy", command=self.copy_text_server)

        self.server_feedback_text.bind("<Button-3>", self.show_server_menu)

    def init_user_menu(self):
        self.user_list_menu = Menu(self.user_list_text, tearoff=0)
        self.user_list_menu.add_command(label="Copy", command=self.copy_text_user)
        self.user_list_menu.add_command(label="Whois", command=self.handle_whois)
        self.user_list_menu.add_command(label="Query", command=self.query_user)

        self.user_list_text.bind("<Button-3>", self.show_user_list_menu)

    def init_channel_menu(self):
        """
        Initialize right-click menu for the channel list.
        """
        self.channel_menu = Menu(self.joined_channels_text, tearoff=0)
        self.joined_channels_text.bind("<Button-3>", self.show_channel_menu)

    def handle_leave_channel(self):
        if self.selected_channel:
            self.irc_client.leave_channel(self.selected_channel)

    def handle_whois(self):
        if hasattr(self, 'selected_nick') and self.selected_nick:
            cleaned_nick = self.selected_nick.replace('+', '').replace('@', '')
            self.irc_client.whois(cleaned_nick)

    def show_channel_menu(self, event):
        try:
            # Get the channel name where the user right-clicked
            self.selected_channel = self.joined_channels_text.get("current linestart", "current lineend").strip()
            
            # Clear the existing menu items
            self.channel_menu.delete(0, 'end')

            if self.selected_channel.startswith("DM:"):  # If it's a DM
                self.channel_menu.add_command(label="Close Query", command=self.close_query)
            else:  # If it's a regular channel
                self.channel_menu.add_command(label="Leave Channel", command=self.handle_leave_channel)

            # Display the context menu
            if self.selected_channel:
                self.channel_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.channel_menu.grab_release()

    def show_user_list_menu(self, event):
        try:
            # Get the nickname where the user right-clicked
            self.selected_nick = self.user_list_text.get("current linestart", "current lineend").strip()
            if self.selected_nick:
                self.user_list_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.user_list_menu.grab_release()

    def show_message_menu(self, event):
        try:
            self.message_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.message_menu.grab_release()

    def show_input_menu(self, event):
        try:
            self.input_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.input_menu.grab_release()

    def show_server_menu(self, event):
        try:
            self.server_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.server_menu.grab_release()

    def cut_text(self):
        self.input_entry.event_generate("<<Cut>>")

    def copy_text(self):
        self.input_entry.event_generate("<<Copy>>")

    def copy_text_message(self):
        self.message_text.event_generate("<<Copy>>")

    def copy_text_server(self):
        self.server_feedback_text.event_generate("<<Copy>>")

    def copy_text_user(self):
        self.user_list_text.event_generate("<<Copy>>")

    def paste_text(self):
        self.input_entry.event_generate("<<Paste>>")

    def select_all_text(self):
        self.input_entry.select_range(0, tk.END)
        self.input_entry.icursor(tk.END)

    def query_user(self):
        target_user = self.selected_nick
        if target_user not in self.irc_client.dm_users:
            self.irc_client.dm_users.append(target_user)
            self.update_message_text(f"DM opened with {target_user}.\r\n")
            self.update_joined_channels_list("DM: " + target_user) 
        else:
            self.update_message_text(f"You already have a DM opened with {target_user}.\r\n")

    def close_query(self):
        target_channel = self.selected_channel

        # Check if the selected channel is a DM
        if target_channel.startswith("DM:"):
            target_user = target_channel.split("DM:")[1].strip()  # Extract the username from the "DM:username" format
            
            if target_user in self.irc_client.dm_users:
                self.irc_client.dm_users.remove(target_user)
                if target_user in self.irc_client.dm_messages:
                    del self.irc_client.dm_messages[target_user]  # Remove chat history
                self.update_message_text(f"DM closed with {target_user}.\r\n")
                self.update_joined_channels_list(None)
            else:
                self.update_message_text(f"You don't have a DM opened with {target_user}.\r\n")
        else:
            pass

    def open_config_window(self):
        config_window = ConfigWindow(self.current_config)
        config_window.mainloop()

    def check_for_channel_list_display(self):
        if self.show_channel_list_flag:
            self.display_channel_list()
            self.show_channel_list_flag = False
        self.after(100, self.check_for_channel_list_display)

    def reset_nick_colors(self):
        self.nickname_colors = {}
        self.update_message_text(f"Nick Colors Reset\r\n")

    def trigger_desktop_notification(self, channel_name=None, title="Ping", message_content=None):
        """
        Show a system desktop notification.
        """
        # Check if the application window is the active window
        if self.is_app_focused():  # If the app is focused, return early
            return

        if channel_name:
            # Ensure channel_name is a string and replace problematic characters
            channel_name = str(channel_name).replace("#", "channel ")
            title = f"{title} from {channel_name}"
            if message_content:
                message = f"{channel_name}: {message_content}"
            else:
                message = f"You've been pinged in {channel_name}!"

        icon_path = os.path.abspath("rude.ico")

        try:
            # Desktop Notification
            notification.notify(
                title=title,
                message=message,
                app_icon=icon_path,  
                timeout=5,  
            )
        except Exception as e:
            print(f"Desktop notification error: {e}")

    def load_ascii_art_macros(self):
        """Load ASCII art from files into a dictionary."""
        ascii_macros = {}
        for file in os.listdir(self.ASCII_ART_DIRECTORY):
            if file.endswith(".txt"):
                with open(os.path.join(self.ASCII_ART_DIRECTORY, file), 'r') as f:
                    macro_name, _ = os.path.splitext(file) 
                    ascii_macros[macro_name] = f.read()
        return ascii_macros

    def reload_ascii_macros(self):
        """Clears and reloads the ASCII art macros from files."""
        self.ASCII_ART_MACROS.clear()  # Clear the current dictionary
        self.ASCII_ART_MACROS = self.load_ascii_art_macros()
        self.update_message_text(f'ASCII art macros reloaded!\r\n') 

    def is_app_focused(self):
        return bool(self.root.focus_displayof())

    def load_config(self):
        """Load the configuration file."""
        # Get the directory of the current script
        script_directory = os.path.dirname(os.path.abspath(__file__))
        
        # Join the directory with the configuration file name to get the absolute path
        config_file_path = os.path.join(script_directory, 'conf.rude')
        
        config = configparser.ConfigParser()
        config.read(config_file_path) 
        
        return dict(config["IRC"])  #convert config to a dictionary

    def switch_channel(self, event):
        # get the selected channel or DM from the clicked position
        index = self.joined_channels_text.index("@%d,%d" % (event.x, event.y))
        line_num = int(index.split(".")[0])
        selection = self.joined_channels_text.get(f"{line_num}.0", f"{line_num}.end").strip()
        self.current_channel = selection

        # Clear the main chat window
        self.clear_chat_window()

        if selection.startswith("DM: "):  # If it's a DM
            user = selection[4:]
            if user in self.irc_client.dm_users:
                self.display_dm_messages(user)  # Display DMs with this user
                self.update_window_title(self.irc_client.nickname, f"DM with {user}")
                self.irc_client.current_channel = user  # Since it's a DM, not a channel
                self.joined_channels_text.tag_remove("dm", f"{line_num}.0", f"{line_num}.end")

        elif selection in self.irc_client.joined_channels:  # If it's a channel
            self.irc_client.current_channel = selection
            self.display_channel_messages()  # Display messages from this channel
            self.update_window_title(self.irc_client.nickname, selection)

        # Highlight the selected channel/DM
        if self.selected_channel:
            self.joined_channels_text.tag_remove("selected", 1.0, tk.END)
        self.joined_channels_text.tag_add("selected", f"{line_num}.0", f"{line_num}.end")
        self.selected_channel = selection

        # Reset the color of the clicked channel by removing the "mentioned" and "activity" tags
        self.joined_channels_text.tag_remove("mentioned", f"{line_num}.0", f"{line_num}.end")
        self.channels_with_mentions = []
        self.joined_channels_text.tag_remove("activity", f"{line_num}.0", f"{line_num}.end")
        if selection in self.channels_with_activity:
            self.channels_with_activity.remove(selection)
        return "break"

    def clear_chat_window(self):
        self.message_text.config(state=tk.NORMAL)
        self.message_text.delete(1.0, tk.END)
        self.message_text.config(state=tk.DISABLED)

    def generate_random_color(self):
        # Randomly pick which channel will be bright
        bright_channel = random.choice(['r', 'g', 'b'])
        
        # Generate random values for each channel
        r = random.randint(50, 255) if bright_channel != 'r' else random.randint(200, 255)
        g = random.randint(50, 255) if bright_channel != 'g' else random.randint(200, 255)
        b = random.randint(50, 255) if bright_channel != 'b' else random.randint(200, 255)

        return "#{:02x}{:02x}{:02x}".format(r, g, b)

    def handle_input(self, event):
        """
        This handles the user input, passes to command parser if needed.
        """
        user_input = self.input_entry.get()
        
        # Check for empty input
        if not user_input:
            return  # Exit the method without doing anything if input is empty
        
        # Add the input to history and adjust the position
        if len(self.input_history) >= self.MAX_HISTORY:
            self.input_history.pop(0)  # Remove the oldest entry if history is full
        self.input_history.append(user_input)
        self.history_position = len(self.input_history)  # Reset the position to the end
        
        timestamp = datetime.datetime.now().strftime('[%H:%M:%S] ')
        if user_input[0] == "/":
            self._command_parser(user_input, user_input[1:].split()[0])
        else:
            self.irc_client.send_message(f'PRIVMSG {self.irc_client.current_channel} :{user_input}')
            self.update_message_text(f'{timestamp} <{self.irc_client.nickname}> {user_input}\r\n')
        self.input_entry.delete(0, tk.END)

    def _command_parser(self, user_input:str, command: str):
        """
        It's the command parser, thanks cow!
        """
        args = user_input[1:].split()
        primary_command = args[0]
        match command:
            case "quit": #exits client.
                self.handle_exit()
            case "disconnect": #disconnects from network.
                self.irc_client.send_message('QUIT')
                time.sleep(1)
                self.irc_client.disconnect()
            case "reconnect": #reconnects to network
                self.irc_client.reconnect()
                # Clear the input entry
            case "connect": #connects to new network.
                server = args[1] if len(args) > 1 else None
                port = int(args[2]) if len(args) > 2 else None
                self.irc_client.reconnect(server, port)
            case "join": #joing channel
                channel_name = user_input.split()[1]
                self.irc_client.join_channel(channel_name)
            case "part": #part channel
                channel_name = user_input.split()[1]
                self.irc_client.leave_channel(channel_name)
            case "query": #open a DM with a user
                target_user = user_input.split()[1] if len(user_input.split()) > 1 else None
                if not target_user:
                    self.update_message_text("Invalid usage. Usage: /query <nickname>\r\n")
                    return
                if target_user not in self.irc_client.dm_users:
                    self.irc_client.dm_users.append(target_user)
                    self.update_message_text(f"DM opened with {target_user}.\r\n")
                    self.update_joined_channels_list("DM: " + target_user) 
                else:
                    self.update_message_text(f"You already have a DM opened with {target_user}.\r\n")
            case "away": # set the user as away
                if len(args) > 1:  # Check if an away message has been provided
                    away_message = ' '.join(args[1:])
                    self.irc_client.send_message(f'AWAY :{away_message}')
                else:  # If no away message, it typically removes the away status.
                    self.irc_client.send_message('AWAY')
            case "back": # remove the "away" status
                self.irc_client.send_message('AWAY')
            case "msg": #send a message to a user
                parts = user_input.split(' ', 2)
                if len(parts) >= 3:
                    receiver = parts[1]
                    message_content = parts[2]
                    self.irc_client.send_message(f'PRIVMSG {receiver} :{message_content}')
                    self.update_message_text(f'<{self.irc_client.nickname} -> {receiver}> {message_content}\r\n')
                else:
                    self.update_message_text(f"Invalid usage. Usage: /msg <nickname> <message_content>\r\n")
            case "cq": #close a DM with a user
                target_user = user_input.split()[1] if len(user_input.split()) > 1 else None
                if not target_user:
                    self.update_message_text("Invalid usage. Usage: /cq <nickname>\r\n")
                    return
                if target_user in self.irc_client.dm_users:
                    self.irc_client.dm_users.remove(target_user)
                    if target_user in self.irc_client.dm_messages:
                        del self.irc_client.dm_messages[target_user]  # Remove chat history
                    self.update_message_text(f"DM closed with {target_user}.\r\n")
                    self.update_joined_channels_list(None)  # Call the update method to refresh the GUI
                else:
                    self.update_message_text(f"You don't have a DM opened with {target_user}.\r\n")
            case "sw": #switch channels.
                channel_name = user_input.split()[1]
                self.irc_client.current_channel = channel_name
                self.display_channel_messages()
                self.update_window_title(self.irc_client.nickname, channel_name)
            case "topic": #requests topic only for right now
                self.irc_client.send_message(f'TOPIC {self.irc_client.current_channel}')
            case "help": #HELP!
                self.display_help()
            case "users": #refreshes user list
                self.irc_client.sync_user_list()
            case "nick": #changes nickname
                new_nickname = user_input.split()[1]
                self.irc_client.change_nickname(new_nickname)
            case "me": #ACTION command
                parts = user_input.split(' ', 1)
                if len(parts) > 1:
                    action_content = parts[1]
                    current_time = datetime.datetime.now().strftime('%H:%M:%S')
                    action_message = f'\x01ACTION {action_content}\x01'
                    self.irc_client.send_message(f'PRIVMSG {self.irc_client.current_channel} :{action_message}')
                    self.update_message_text(f'[{current_time}] * {self.irc_client.nickname} {action_content}\r\n')
                else:
                    self.update_message_text("Invalid usage. Usage: /me <action_content>\r\n")
            case "whois": #who is that?
                target = user_input.split()[1]
                self.irc_client.whois(target)
            case "who":
                self.handle_who_command(args[1:])
            case "ping": #PNOG
                parts = user_input.split()
                target = parts[1] if len(parts) > 1 else None
                self.irc_client.ping_server(target)
            case "clear": #Clears the screen
                self.clear_chat_window()
            case "ignore": #ignores a user
                user_to_ignore = " ".join(user_input.split()[1:])
                if user_to_ignore:
                    if user_to_ignore not in self.irc_client.ignore_list:
                        self.irc_client.ignore_list.append(user_to_ignore)
                        self.update_message_text(f"You've ignored {user_to_ignore}.\r\n")
                    else:
                        self.update_message_text(f"{user_to_ignore} is already in your ignore list.\r\n")
                else:
                    self.update_message_text("Invalid usage. Usage: /ignore <nickname|hostmask>\r\n")
            case "unignore": #unignores a user
                user_to_unignore = user_input.split()[1]
                if user_to_unignore in self.irc_client.ignore_list:
                    self.irc_client.ignore_list.remove(user_to_unignore)
                    self.update_message_text(f"You've unignored {user_to_unignore}.\r\n")
                else: 
                    self.update_message_text(f"{user_to_unignore} is not in your ignore list.\r\n")
            case "sa": #sends to all channels
                message = ' '.join(user_input.split()[1:])
                for channel in self.irc_client.joined_channels:
                    self.irc_client.send_message(f'PRIVMSG {channel} :{message}')
                self.update_message_text(f'Message sent to all joined channels: {message}\r\n')
            case "friend": #adds friend
                friend_name = user_input.split()[1]
                if friend_name not in self.irc_client.friend_list:
                    self.irc_client.friend_list.append(friend_name)
                    self.irc_client.save_friend_list()
                    self.update_message_text(f"{friend_name} added to friends.\r\n")
                else:
                    self.update_message_text(f"{friend_name} is already in your friend list.\r\n")
            case "unfriend": #removes friend
                unfriend_name = user_input.split()[1]
                if unfriend_name in self.irc_client.friend_list:
                    self.irc_client.friend_list.remove(unfriend_name)
                    self.irc_client.save_friend_list()
                    self.update_message_text(f"{unfriend_name} removed from friends.\r\n")
                else:
                    self.update_message_text(f"{unfriend_name} is not in your friend list.\r\n")
            case "CTCP":
                if len(args) < 3:
                    self.update_message_text("Invalid usage. Usage: /CTCP <nickname> <command> [parameters]\r\n")
                    return
                target = args[1]
                ctcp_command = args[2].upper()
                parameter = ' '.join(args[3:]) if len(args) > 3 else None
                self.irc_client.send_ctcp_request(target, ctcp_command, parameter)
            case "motd":
                self.irc_client.send_message('MOTD')
            case "time":
                self.irc_client.send_message('TIME')
            case "list":
                self.irc_client.send_message('LIST')
            case "mac":
                self.handle_mac_command(args)
            case "syscowsay":
                self.handle_syscowsay_command(args)
            case "sysfortune":
                self.handle_sysfortune_command(args[1:])
            case "roll":  
                self.dice_roll(args)
            case "exec":
                self._handle_exec_command(args)
            case "mode":
                self.handle_mode_command(args)
            case "notice":
                self.handle_notice_command(args)
            case "invite":
                self.handle_invite_command(args)
            case "kick":
                self.handle_kick_command(args)
            case "fortune":
                file_name_arg = args[1] if len(args) > 1 else None
                self.fortune(file_name_arg)
            case "cowsay":
                self.handle_cowsay_command(args)
            case _:
                self.update_message_text(f"Unkown Command! Type '/help' for help.\r\n")
        self.input_entry.delete(0, tk.END)

    def handle_cowsay_command(self, args):
        script_directory = os.path.dirname(os.path.abspath(__file__))

        if len(args) > 1:
            file_name_arg = args[1]
            # Construct the potential file path using the absolute path
            potential_path = os.path.join(script_directory, "Fortune Lists", f"{file_name_arg}.txt")

            # Check if the provided argument corresponds to a valid fortune file
            if os.path.exists(potential_path):
                self.fortune_cowsay(file_name_arg)
            else:
                # If not a valid file name, consider the rest of the arguments as a custom message
                custom_message = ' '.join(args[1:])
                self.cowsay_custom_message(custom_message)
        else:
            self.fortune_cowsay()

    def navigate_history(self, event):
        """Navigate through the input history using the arrow keys."""
        if event.keysym == 'Up':
            # Move to the previous history entry
            self.history_position = max(0, self.history_position - 1)
            self.show_history_entry()
        elif event.keysym == 'Down':
            # Move to the next history entry
            self.history_position = min(len(self.input_history) - 1, self.history_position + 1)
            self.show_history_entry()

    def show_history_entry(self):
        """Display the history entry at the current position in the input field."""
        if 0 <= self.history_position < len(self.input_history):
            entry = self.input_history[self.history_position]
            self.input_entry.delete(0, tk.END)  # Clear current input
            self.input_entry.insert(tk.END, entry)  # Insert the history entry

    def cowsay(self, message):
        """Formats the given message in a 'cowsay' format."""

        # Find the longest line in the input message to determine the maximum width.
        max_line_length = max(len(line) for line in message.split('\n'))
        # Adjust for the added spaces and border characters
        adjusted_width = max_line_length - 4  # 2 for initial and end space + 2 for border characters

        # Manually split lines to check for one-word lines.
        raw_lines = message.split('\n')
        wrapped_lines = []
        for line in raw_lines:
            if len(line.split()) == 1:  # Single word line
                wrapped_lines.append(line)
            else:
                wrapped_lines.extend(textwrap.wrap(line, adjusted_width))

        # Format lines using cowsay style.
        if len(wrapped_lines) == 1:
            # Special case: single line message.
            combined_message = f"/ {wrapped_lines[0].ljust(adjusted_width)} \\"
        else:
            lines = [f"/ {wrapped_lines[0].ljust(adjusted_width)} \\"]
            for line in wrapped_lines[1:-1]:
                lines.append(f"| {line.ljust(adjusted_width)} |")
            lines.append(f"\\ {wrapped_lines[-1].ljust(adjusted_width)} /")
            combined_message = '\n'.join(lines)

        # Find the longest line again (after formatting) to adjust the borders accordingly.
        max_line_length = max(len(line) for line in combined_message.split('\n'))

        top_border = ' ' + '_' * (max_line_length - 2)
        
        # Set the bottom border to match the max line length
        bottom_border = ' ' + '-' * (max_line_length - 2)

        cow = """
       \\   ^__^
        \\  (oo)\\_______
           (__)\\       )\\/\\
               ||----w |
               ||     ||"""

        return f"{top_border}\n{combined_message}\n{bottom_border}{cow}"

    def wrap_text(self, text, width=100):
        """Dont spam that channel"""
        return textwrap.fill(text, width)

    def get_fortune_file(self, file_name=None):
        script_directory = os.path.dirname(os.path.abspath(__file__))
        fortune_directory = os.path.join(script_directory, "Fortune Lists")
        
        if file_name:
            return os.path.join(fortune_directory, file_name + ".txt")
        
        fortune_files = [os.path.join(fortune_directory, f) for f in os.listdir(fortune_directory) if f.endswith('.txt')]
        return random.choice(fortune_files)

    def fortune_cowsay(self, file_name=None):
        file_name = self.get_fortune_file(file_name)

        with open(file_name, 'r') as f:
            fortunes = f.read().strip().split('%')
            chosen_fortune = random.choice(fortunes).strip()

        wrapped_fortune_text = self.wrap_text(chosen_fortune)
        cowsay_fortune = self.cowsay(wrapped_fortune_text)
        for line in cowsay_fortune.split('\n'):
            self.irc_client.send_message(f'PRIVMSG {self.irc_client.current_channel} :{line}')
            self.update_message_text(line + "\r\n")
            time.sleep(0.4)

    def cowsay_custom_message(self, message):
        """Wrap a custom message using the cowsay format."""
        wrapped_message = self.wrap_text(message)
        cowsay_output = self.cowsay(wrapped_message)
        
        for line in cowsay_output.split('\n'):
            self.irc_client.send_message(f'PRIVMSG {self.irc_client.current_channel} :{line}')
            self.update_message_text(line + "\r\n")
            time.sleep(0.4)

    def fortune(self, file_name=None):
        """Choose a random fortune from one of the lists"""
        file_name = self.get_fortune_file(file_name)

        with open(file_name, 'r') as f:
            fortunes = f.read().strip().split('%')
            chosen_fortune = random.choice(fortunes).strip()

        for line in chosen_fortune.split('\n'):
            self.irc_client.send_message(f'PRIVMSG {self.irc_client.current_channel} :{line}')
            self.update_message_text(line + "\r\n")
            time.sleep(0.4)

    def dice_roll(self, args):
        # Default to d20 if no arguments are provided
        die_type = "d20" if len(args) < 2 else args[1].lower()
        
        # Map the die type to its maximum value
        dice_map = {
            "d4": 4,
            "d6": 6,
            "d8": 8,
            "d10": 10,
            "d100": 100,
            "d12": 12,
            "d20": 20,
            "d120": 120
        }

        # Check if the die_type is in the predefined dice_map or if it's a custom dice size (e.g., d25, d30, etc.)
        if die_type in dice_map:
            max_value = dice_map[die_type]
        elif re.match(r'd(\d+)', die_type):
            max_value = int(re.match(r'd(\d+)', die_type).group(1))
        else:
            self.update_message_text(f"Invalid die type: {die_type}.\r\n")
            return

        number = random.randint(1, max_value)
        timestamp = datetime.datetime.now().strftime('[%H:%M:%S] ')

        action_message = f"\x01ACTION rolled a {number} on a {die_type}\x01"
        display_message = f"{timestamp} * {self.irc_client.nickname} rolled a {number} on a {die_type}"

        self.update_message_text(display_message + "\r\n")
        self.irc_client.send_message(f'PRIVMSG {self.irc_client.current_channel} :{action_message}')

    def handle_who_command(self, args):
        """
        Handle the WHO command entered by the user.
        """
        if not args:
            # General WHO
            self.irc_client.send_message('WHO')
        elif args[0].startswith('#'):
            # WHO on a specific channel
            channel = args[0]
            self.irc_client.send_message(f'WHO {channel}')
        else:
            # WHO with mask or user host
            mask = args[0]
            self.irc_client.send_message(f'WHO {mask}')

    def handle_kick_command(self, args):
        if len(args) < 3:
            self.update_message_text("Usage: /kick <user> <channel> [reason]\r\n")
            return
        user = args[1]
        channel = args[2]
        reason = ' '.join(args[3:]) if len(args) > 3 else None
        kick_message = f'KICK {channel} {user}' + (f' :{reason}' if reason else '')
        self.irc_client.send_message(kick_message)
        self.update_message_text(f"Kicked {user} from {channel} for {reason}\r\n")

    def handle_invite_command(self, args):
        if len(args) < 3:
            self.update_message_text("Usage: /invite <user> <channel>\r\n")
            return
        user = args[1]
        channel = args[2]
        self.irc_client.send_message(f'INVITE {user} {channel}\r\n')
        self.update_message_text(f"Invited {user} to {channel}\r\n")

    def handle_mode_command(self, args):
        if len(args) < 3:
            self.update_message_text("Usage: /mode <target> <mode>\r\n")
            return
        target = args[1]
        mode = args[2]
        self.irc_client.send_message(f'MODE {target} {mode}\r\n')
        self.update_message_text(f"Set mode {mode} for {target}\r\n")

    def handle_notice_command(self, args):
        if len(args) < 3:
            self.update_message_text("Usage: /notice <target> <message>\r\n")
            return
        target = args[1]
        message = ' '.join(args[2:])
        self.irc_client.send_message(f'NOTICE {target} :{message}\r\n')
        self.update_message_text(f"Sent NOTICE to {target}: {message}\r\n")

    def _handle_exec_command(self, args):
        """
        Executes an OS command and sends its output to the current IRC channel line by line.
        """
        os_command = ' '.join(args[1:])
        try:
            # Run the command and capture its output
            result = subprocess.run(os_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output_lines = (result.stdout + result.stderr).splitlines()
            
            for line in filter(lambda l: l.strip(), output_lines):  # Skip empty or whitespace-only lines
                # Send the line to the current IRC channel
                self.irc_client.send_message(f'PRIVMSG {self.irc_client.current_channel} :{line}')
                # Update the GUI with the message
                self.update_message_text(line + "\r\n")
                time.sleep(0.5)

        except Exception as e:
            self.update_message_text(f"Error executing command: {e}\r\n")

    def handle_mac_command(self, args):
        if len(args) < 2:
            available_macros = ", ".join(self.ASCII_ART_MACROS.keys())
            self.update_message_text(f"Available ASCII art macros: {available_macros}\r\n")
            self.update_message_text("Usage: /mac <macro_name>\r\n")
            return

        macro_name = args[1]
        if macro_name in self.ASCII_ART_MACROS:
            current_time = datetime.datetime.now().strftime('%H:%M:%S')
            for line in self.ASCII_ART_MACROS[macro_name].splitlines():
                self.irc_client.send_message(f'PRIVMSG {self.irc_client.current_channel} :{line}')
                time.sleep(0.5)
                formatted_line = f"[{current_time}]  <{self.irc_client.nickname}> {line}\r\n"
                self.update_message_text(formatted_line)
        else:
            self.update_message_text(f"Unknown ASCII art macro: {macro_name}. Type '/mac' to see available macros.\r\n")

    def handle_syscowsay_command(self, args):
        try:
            # Determine if we're dealing with a category, custom message, or default
            if len(args) == 1:
                message = self.cowsay_fortune()  # Default random fortune
            elif len(args) == 2 and self.is_fortune_category(args[1]):
                message = self.cowsay_fortune(category=args[1])  # Specific fortune category
            else:
                message = self.cowsay_custom(' '.join(args[1:]))  # Custom message

            # Send the message to the channel
            for line in message.split("\n"):
                if not line.strip():
                    continue

                self.irc_client.send_message(f'PRIVMSG {self.irc_client.current_channel} :{line}')
                time.sleep(0.3)

                current_time = datetime.datetime.now().strftime('%H:%M:%S')
                formatted_line = f"[{current_time}]  <{self.irc_client.nickname}> {line}"
                self.update_message_text(formatted_line + "\r\n")
        except Exception as e:
            self.update_message_text(f"Error executing cowsay: {e}\r\n")

    def is_fortune_category(self, category):
        try:
            # Attempt to get a fortune for the category; if it fails, it's not a valid category
            subprocess.check_output(f"fortune {category}", shell=True)
            return True
        except:
            return False

    def cowsay_fortune(self, category=None):
        cow_mode = {
            1: "-b",
            2: "-d",
            3: "",  # default
            4: "-g",
            5: "-p",
            6: "-s",
            7: "-t",
            8: "-w",
            9: "-y"
        }

        rng = random.randint(1, 9)

        # Getting the list of cowfiles
        result = subprocess.run(['cowsay', '-l'], capture_output=True, text=True)
        cowfiles = result.stdout.split()[1:]
        cowfile = random.choice(cowfiles)

        # Running the fortune with cowsay command
        if category:
            fortune_result = subprocess.run(['fortune', '-s', category], capture_output=True, text=True)
        else:
            fortune_result = subprocess.run(['fortune', '-s'], capture_output=True, text=True)
        
        cowsay_command = ['cowsay', '-W', '100', cow_mode[rng], '-f', cowfile]
        print(f"DEBUG: Running cowsay command: {fortune_result} {' '.join(cowsay_command)}")
        cowsay_result = subprocess.run(cowsay_command, input=fortune_result.stdout, capture_output=True, text=True)

        return cowsay_result.stdout

    def cowsay_custom(self, message):
        # Just a simple cowsay with the provided message
        cowsay_result = subprocess.run(['cowsay', '-W', '100', '-f', 'flaming-sheep'], input=message, capture_output=True, text=True)
        return cowsay_result.stdout

    def handle_sysfortune_command(self, args=[]):
        import shlex
        try:
            # Build the fortune command with the given arguments.
            # We use shlex.quote to safely escape any argument passed to the command.
            fortune_args = ' '.join(shlex.quote(arg) for arg in args)
            command = f"fortune -as {fortune_args}"
            result = subprocess.check_output(command, shell=True).decode('utf-8')
            
            for line in result.split("\n"):
                if not line.strip():
                    continue
                self.irc_client.send_message(f'PRIVMSG {self.irc_client.current_channel} :{line}')
                current_time = datetime.datetime.now().strftime('%H:%M:%S')
                formatted_line = f"[{current_time}]  <{self.irc_client.nickname}> {line}"
                self.update_message_text(formatted_line + "\r\n")
        except Exception as e:
            self.update_message_text(f"Error executing fortune: {e}\r\n")

    def display_help(self):
        # === General & Utility Commands ===
        self.update_message_text("=== General & Utility Commands ===\r\n")
        self.update_message_text(f'/help - Display this help menu\r\n')
        self.update_message_text(f'/clear - Clear the chat window\r\n')
        self.update_message_text(f'Exit button - Send /quit and close client\r\n')
        self.update_message_text(f'Tab - Auto-complete nicknames\r\n')
        self.update_message_text(f'/mac to see available macros /mac <macroname> sends that macro\r\n')

        # === Connection & Server Commands ===
        self.update_message_text("\r\n=== Connection & Server Commands ===\r\n")
        self.update_message_text(f'/connect <server> <port> - Connect to a specific server\r\n')
        self.update_message_text(f'/disconnect - Disconnect from the server\r\n')
        self.update_message_text(f'/reconnect - Reconnect to the last server\r\n')
        self.update_message_text(f'/quit - Close connection and exit client\r\n')
        self.update_message_text(f'/ping - Ping the connected server or /ping <usernick> to ping a specific user\r\n')
        self.update_message_text(f'/who - Shows who is on the channel or server\r\n')
        self.update_message_text(f'/motd - View Message of the Day\r\n')
        self.update_message_text(f'/time - Check server time\r\n')
        self.update_message_text(f'/list - List available channels\r\n')

        # === Channel & Message Management ===
        self.update_message_text("\r\n=== Channel & Message Management ===\r\n")
        self.update_message_text(f'/join <channel> - Join a channel\r\n')
        self.update_message_text(f'/part <channel> - Leave a channel\r\n')
        self.update_message_text(f'/sw <channel> - Switch to a given channel. Clicking on channels also switches\r\n')
        self.update_message_text(f'/msg <nickname> <message> - Send a direct message, e.g., /msg NickServ IDENTIFY\r\n')
        self.update_message_text(f'/query <nickname> - Open a DM with a user\r\n')
        self.update_message_text(f'/cq <nickname> - Close the DM with a user\r\n')
        self.update_message_text(f'/sa - Send a message to all joined channels\r\n')
        self.update_message_text(f'/notice - Sends a notice message\r\n')
        self.update_message_text(f'/invite - Invites a user to a channel\r\n')
        self.update_message_text(f'/kick - Kicks a user from a channel\r\n')

        # === User & Interaction Commands ===
        self.update_message_text("\r\n=== User & Interaction Commands ===\r\n")
        self.update_message_text(f'/whois <nickname> - Whois a specific user\r\n')
        self.update_message_text(f'/ignore <nickname> & /unignore <nickname> - Ignore/Unignore a user\r\n')
        self.update_message_text(f'/friend <nickname> - Add a user to your friend list\r\n')
        self.update_message_text(f'/unfriend <nickname> - Remove a user from your friend list\r\n')
        self.update_message_text(f'/away to set yourself as away\r\n')
        self.update_message_text(f'/back to return (removes AWAY status)\r\n')
        self.update_message_text(f'/mode - Sets or removes user/channel modes\r\n')

        # === Advanced & Fun Commands ===
        self.update_message_text("\r\n=== Advanced & Fun Commands ===\r\n")
        self.update_message_text(f'/CTCP <nickname> <command> [parameters] - CTCP command, e.g., /CTCP Rudie CLIENTINFO\r\n')
        self.update_message_text(f'/syscowsay to generate and send a cowsay to the channel\r\n')
        self.update_message_text(f'/cowsay to generate and send a cowsay to the channel\r\n')
        self.update_message_text(f'/sysfortune to tell fortune. /sysfortune <library> gives a fortune from that library\r\n')
        self.update_message_text(f'/fortune to tell fortune. /fortune <library> gives a fortune from that library\r\n')
        self.update_message_text(f'/exec command will run the following command on your machine and output to the channel youre in\r\n')
        self.update_message_text(f'Example: /exec ping -c 1 www.google.com\r\n')
        self.update_message_text(f'Note: syscowsay & sysfortune will only work if you have both installed on your LINUX system\r\n')
        self.update_message_text(f'Note: cowsay & fortune are internal within the client and will pull from the Fortune Lists folder\r\n')

    def format_message_for_display(self, message):
        # Remove color codes
        message_no_colors = re.sub(r'\x03(\d{1,2}(,\d{1,2})?)?', '', message)

        # Define patterns for bold, italic, and reset
        bold_pattern = r'\x02(.*?)(?:\x02|\x0F|$)'  # Modified to make the closing code optional and also check for end of string
        italic_pattern = r'\x1D(.*?)(?:\x1D|\x0F|$)'  # Modified similarly

        # Function to extract ranges from matches
        def get_ranges(pattern, msg):
            ranges = []
            for match in re.finditer(pattern, msg):
                start = match.start()
                end = match.end()
                for group in match.groups():
                    if group is not None:
                        end = start + len(group) + 2  
                        ranges.append((start, end - 1))
                        break
            return ranges

        bold_ranges = get_ranges(bold_pattern, message_no_colors)
        italic_ranges = get_ranges(italic_pattern, message_no_colors)

        # For bold-italic, we'll look for overlapping ranges
        bold_italic_ranges = set([(b_start, b_end) for b_start, b_end in bold_ranges 
                                  for i_start, i_end in italic_ranges 
                                  if b_start <= i_start and b_end >= i_end])

        # Remove the formatting characters to get the formatted message
        formatted_message = re.sub(r'[\x02\x1D\x0F]', '', message_no_colors)

        return formatted_message, bold_ranges, italic_ranges, list(bold_italic_ranges)

    def display_dm_messages(self, user):
        if user in self.irc_client.dm_messages:
            displayed_messages = set()  # Use a set to track unique messages
            for message in self.irc_client.dm_messages[user]:
                if message not in displayed_messages:
                    self.update_message_text(message)
                    displayed_messages.add(message)

    def update_server_feedback_text(self, message):
        """
        This updates the server feedback, it takes into account ascii.
        """
        def update_text(message_to_update):
            message_to_update = message_to_update.replace('\r', '')
            formatted_message, bold_ranges, italic_ranges, bold_italic_ranges = self.format_message_for_display(message_to_update)

            # Insert the message into the Text widget
            self.server_feedback_text.config(state=tk.NORMAL)
            start_index = self.server_feedback_text.index(tk.END)  # Get the starting index for this message
            self.server_feedback_text.insert(tk.END, formatted_message + "\n", "server_feedback")
            self.server_feedback_text.config(state=tk.DISABLED)

            # Apply bold formatting
            for start, end in bold_ranges:
                start_bold_index = f"{start_index}+{start}c"
                end_bold_index = f"{start_index}+{end}c"
                self.server_feedback_text.tag_add("bold", start_bold_index, end_bold_index)

            # Apply italic formatting
            for start, end in italic_ranges:
                start_italic_index = f"{start_index}+{start}c"
                end_italic_index = f"{start_index}+{end}c"
                self.server_feedback_text.tag_add("italic", start_italic_index, end_italic_index)

            # Apply bold-italic formatting
            for start, end in bold_italic_ranges:
                start_bold_italic_index = f"{start_index}+{start}c"
                end_bold_italic_index = f"{start_index}+{end}c"
                self.server_feedback_text.tag_add("bold_italic", start_bold_italic_index, end_bold_italic_index)

            # Ensure the message is visible in the widget
            self.server_feedback_text.see(tk.END)
            self.server_feedback_text.tag_configure("server_feedback", foreground="#7882ff")  # Make the server output blue

        # Schedule the update_text function to be run in the main thread
        self.root.after(0, lambda: update_text(message))

    def update_user_list(self, channel):
        """
        This is responsible for updating the user list within the GUI.
        """
        current_position = self.user_list_text.yview()
        if channel in self.irc_client.user_list:
            users = self.irc_client.user_list[channel]

            # Sort users based on symbols @, +, and none
            users_sorted = sorted(users, key=lambda user: (not user.startswith('@'), not user.startswith('+'), user))

            user_list_text = "\n".join(users_sorted)
        else:
            user_list_text = "No users in the channel."

        self.user_list_text.config(state=tk.NORMAL)
        self.user_list_text.delete(1.0, tk.END)
        self.user_list_text.insert(tk.END, user_list_text)
        self.user_list_text.config(state=tk.DISABLED)
        self.user_list_text.yview_moveto(current_position[0])

    def update_joined_channels_list(self, channel):
        """
        This handles all the fancy tags for channel notifications, mentions, etc.
        """
        # Create tags for highlighting
        self.joined_channels_text.tag_configure("selected", background="#2375b3")
        self.joined_channels_text.tag_configure("mentioned", background="red")
        self.joined_channels_text.tag_configure("activity", background="green")
        self.joined_channels_text.tag_configure("green_text", foreground="#39ff14")
        
        # Set certain tags to raise over others.
        self.joined_channels_text.tag_raise("selected")
        self.joined_channels_text.tag_raise("mentioned")

        # Combine channels and DM users for display
        all_items = self.irc_client.joined_channels + [f"DM: {user}" for user in self.irc_client.dm_users]
        all_items_text = "\n".join(all_items)

        self.joined_channels_text.config(state=tk.NORMAL)
        self.joined_channels_text.delete(1.0, tk.END)
        self.joined_channels_text.insert(tk.END, all_items_text)

        # Remove the "selected" tag from the entire text widget
        self.joined_channels_text.tag_remove("selected", "1.0", tk.END)

        # Iterate through the lines in the joined_channels_text widget
        for idx, line in enumerate(self.joined_channels_text.get("1.0", tk.END).splitlines()):
            if line in self.channels_with_activity:  # apply the "activity" tag first
                self.joined_channels_text.tag_add("activity", f"{idx + 1}.0", f"{idx + 1}.end")
            if line in self.channels_with_mentions:  # then apply the "mentioned" tag
                self.joined_channels_text.tag_add("mentioned", f"{idx + 1}.0", f"{idx + 1}.end")
            if line == self.irc_client.current_channel or line == f"DM: {self.irc_client.current_channel}":  # apply the "selected" tag if it's the current channel or DM
                self.joined_channels_text.tag_add("selected", f"{idx + 1}.0", f"{idx + 1}.end")
                self.update_window_title(self.irc_client.nickname, self.irc_client.current_channel)  # using the actual current channel or DM

        ascii_art = """
        .-.-.
       (_\\|/_)
       ( /|\\ )    
        '-'-'`-._"""
        
        # Add the ASCII art at the end
        self.joined_channels_text.insert(tk.END, "\n" + ascii_art)
        start_index = self.joined_channels_text.index(tk.END + "- {} lines linestart".format(ascii_art.count("\n") + 1))
        end_index = self.joined_channels_text.index(tk.END)
        self.joined_channels_text.tag_add("green_text", start_index, end_index)

        self.joined_channels_text.config(state=tk.DISABLED)

    def handle_exit(self):
        """
        Gracefully exits
        """
        self.irc_client.save_ignore_list()
        self.irc_client.save_friend_list()
        self.irc_client.exit_event.set() 
        
        # Check if the socket is still open before attempting to shut it down
        if hasattr(self.irc_client, 'irc'):
            try:
                self.irc_client.send_message('QUIT')
                self.irc_client.irc.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                if e.errno == 9:  # Bad file descriptor
                    print("Socket already closed.")
                else:
                    print(f"Unexpected error during socket shutdown: {e}")
        
        self.root.destroy()

    def handle_tab_complete(self, event):
        """
        Tab complete with cycling through possible matches.
        """
        # Get the current input in the input entry field
        user_input = self.input_entry.get()
        cursor_pos = self.input_entry.index(tk.INSERT)

        # Update the regex to match alphanumeric, underscores, dashes, square brackets, curly braces, backslash, backticks, and pipes
        match = re.search(r'\b[\]\w\-^[{}\\`|]+$', user_input[:cursor_pos])
        if not match:
            return
        partial_nick = match.group()

        # Cancel any previous timers
        if hasattr(self, 'tab_completion_timer'):
            self.root.after_cancel(self.tab_completion_timer)

        # Get the user list for the current channel
        current_channel = self.irc_client.current_channel
        if current_channel in self.irc_client.user_list:
            user_list = self.irc_client.user_list[current_channel]
        else:
            return

        # Remove @ and + symbols from nicknames
        user_list_cleaned = [nick.lstrip('@+') for nick in user_list]

        # Initialize or update completions list
        if not hasattr(self, 'tab_complete_completions') or not hasattr(self, 'last_tab_time') or (time.time() - self.last_tab_time) > 1.0:
            self.tab_complete_completions = [nick for nick in user_list_cleaned if nick.startswith(partial_nick)]
            self.tab_complete_index = 0

        # Update the time of the last tab press
        self.last_tab_time = time.time()

        if self.tab_complete_completions:
            # Fetch the next completion
            completed_nick = self.tab_complete_completions[self.tab_complete_index]
            remaining_text = user_input[cursor_pos:]
            completed_text = user_input[:cursor_pos - len(partial_nick)] + completed_nick + remaining_text
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, completed_text)
            # Cycle to the next completion
            self.tab_complete_index = (self.tab_complete_index + 1) % len(self.tab_complete_completions)

        # Set up a timer to append ": " after half a second if no more tab presses
        self.tab_completion_timer = self.root.after(500, self.append_colon_to_nick)

        # Prevent default behavior of the Tab key
        return 'break'

    def append_colon_to_nick(self):
        current_text = self.input_entry.get()
        self.input_entry.delete(0, tk.END)
        self.input_entry.insert(0, current_text + ": ")

    def update_window_title(self, nickname, channel_name):
        """
        This provides some fancy feedback when switching channels. 
        """
        title_parts = []
        if nickname:
            title_parts.append(nickname)
        if channel_name:
            title_parts.append(channel_name)
        if title_parts:
            self.root.title("RudeChat " + " | ".join(title_parts))
        else:
            self.root.title("RudeChat ")

        self.nickname_label.config(font=("Hack", 9, "bold italic"), text=f"{channel_name} $ {nickname} $> ")

    def update_message_text(self, text, sender=None, is_dm=False):
        """
        This method is responsible for updating the message text, it adds tags for the users nick, colors the other users nicks, and chooses the color for the main text. 
        """
        def _update_message_text():
            self.message_text.config(state=tk.NORMAL)
                
            # Process the message for bold, italic, and bold-italic formatting
            formatted_text, bold_ranges, italic_ranges, bold_italic_ranges = self.format_message_for_display(text)
                
            # Remove trailing '\r' characters from each line
            cleaned_formatted_text = "\n".join([line.rstrip('\r') for line in formatted_text.split('\n')])

            start_insert_index = self.message_text.index(tk.END)

            self.message_text.insert(tk.END, cleaned_formatted_text)
            
            self._apply_formatting(cleaned_formatted_text, bold_ranges, italic_ranges, bold_italic_ranges, start_insert_index)
                
            self.message_text.config(state=tk.DISABLED)
            self.message_text.see(tk.END)

        self.root.after(0, _update_message_text)
        
    def _apply_formatting(self, cleaned_formatted_text, bold_ranges, italic_ranges, bold_italic_ranges, start_insert_index):
        # Process nicknames and color them
        start_idx = "1.0"
        while True:
            # Find the opening '<'
            start_idx = self.message_text.search('<', start_idx, stopindex=tk.END)
            if not start_idx:
                break
            # Find the closing '>' ensuring no newlines between
            end_idx = self.message_text.search('>', start_idx, f"{start_idx} lineend")
            if end_idx:
                end_idx = f"{end_idx}+1c"  # Include the '>' character
                # Extract the nickname
                nickname = self.message_text.get(start_idx + "+1c", end_idx + "-1c")

                # If nickname doesn't have an assigned color, generate one
                if nickname not in self.nickname_colors:
                    self.nickname_colors[nickname] = self.generate_random_color()
                nickname_color = self.nickname_colors[nickname]

                # If it's the main user's nickname, set color to green
                if nickname == self.irc_client.nickname:
                    nickname_color = "#39ff14"

                self.message_text.tag_configure(f"nickname_{nickname}", foreground=nickname_color)
                self.message_text.tag_add(f"nickname_{nickname}", start_idx, end_idx)
                start_idx = end_idx
            else:
                start_idx = f"{start_idx}+1c"

        main_user_name = self.irc_client.nickname
        start_idx = "1.0"
        while True:
            start_idx = self.message_text.search(main_user_name, start_idx, stopindex=tk.END)
            if not start_idx:
                break
            end_idx = f"{start_idx}+{len(main_user_name)}c"
            self.message_text.tag_configure("main_user_color", foreground="#39ff14")
            self.message_text.tag_add("main_user_color", start_idx, end_idx)
            start_idx = end_idx

            # Check if the start index has reached the end of the text
            if start_idx == tk.END:
                break

        urls = self.find_urls(cleaned_formatted_text)
        for index, url in enumerate(urls):
            # Mark found URLs in the text to avoid them being treated as channels
            cleaned_formatted_text = cleaned_formatted_text.replace(url, f"<URL>{url}</URL>")
            start_idx = "1.0"
            while True:
                start_idx = self.message_text.search(url, start_idx, tk.END)
                if not start_idx:
                    break
                end_idx = f"{start_idx}+{len(url)}c"
                
                # Create a unique tag for each URL
                url_tag = f"url_{index}_{start_idx}"  # Make it unique per occurrence
                
                self.message_text.tag_add(url_tag, start_idx, end_idx)
                self.message_text.tag_configure(url_tag, foreground="blue", underline=1)
                
                # Bind the URL to the open_url method using partial
                self.message_text.tag_bind(url_tag, "<Button-1>", partial(self.open_url, url=url))
                
                # Move the start index to after the current found URL to continue the search
                start_idx = end_idx

        channels = self.find_channels(cleaned_formatted_text)
        for channel in channels:
            start_idx = "1.0"
            while True:
                # Search for the channel from the current start index
                start_idx = self.message_text.search(channel, start_idx, stopindex=tk.END)
                if not start_idx:
                    break
                end_idx = f"{start_idx}+{len(channel)}c"
                
                # Ensure we're not treating marked URLs as channels
                if "<URL>" not in self.message_text.get(start_idx, end_idx) and "</URL>" not in self.message_text.get(start_idx, end_idx):
                    tag_name = f"channel_{channel}"  # Create a unique tag for the channel
                    self.message_text.tag_add(tag_name, start_idx, end_idx)
                    self.message_text.tag_configure(tag_name, foreground="cyan", underline=1)
                    self.message_text.tag_bind(tag_name, "<Button-1>", lambda e, ch=channel: self.join_channel(ch))
                
                # Move the start index to after the current found channel to continue the search
                start_idx = end_idx

        # Apply bold formatting
        for start, end in bold_ranges:
            if (start, end) not in bold_italic_ranges:  
                start_idx = f"{start_insert_index}+{start}c"
                end_idx = f"{start_insert_index}+{end}c"
                self.message_text.tag_add("bold", start_idx, end_idx)
                self.message_text.tag_configure("bold", font=self.bold_font)

        # Apply italic formatting
        for start, end in italic_ranges:
            if (start, end) not in bold_italic_ranges:  
                start_idx = f"{start_insert_index}+{start}c"
                end_idx = f"{start_insert_index}+{end}c"
                self.message_text.tag_add("italic", start_idx, end_idx)
                self.message_text.tag_configure("italic", font=self.italic_font)

        # Apply bold-italic formatting
        for start, end in bold_italic_ranges:
            start_idx = f"{start_insert_index}+{start}c"
            end_idx = f"{start_insert_index}+{end}c"
            self.message_text.tag_add("bold_italic", start_idx, end_idx)
            self.message_text.tag_configure("bold_italic", font=self.bold_italic_font)

        # Adjusting tag priorities at the end
        if self.message_text.tag_ranges("bold_italic"):
            self.message_text.tag_raise("bold_italic")
        if self.message_text.tag_ranges("bold"):
            self.message_text.tag_raise("bold")
        if self.message_text.tag_ranges("italic"):
            self.message_text.tag_raise("italic")

        # apply #C0FFEE text color
        #self.message_text.tag_configure("brightgreen", foreground="#C0FFEE")
        #self.message_text.tag_add("brightgreen", "1.0", "end")

    def display_channel_messages(self):
        """
        This is responsible for showing the channels scrollback / history
        """
        channel = self.irc_client.current_channel
        if channel in self.irc_client.channel_messages:
            messages = self.irc_client.channel_messages[channel]
            text = ''
            for message_data in messages:
                if len(message_data) == 3:
                    timestamp, sender, message = message_data
                    # Check if the message is already formatted with the sender's nickname for CTCP ACTION
                    if message.startswith('* '):
                        text += f'{timestamp} {message}\n'
                    else:
                        text += f'{timestamp} <{sender}> {message}\n'
                else:  # Assuming the other format is (timestamp, formatted_message)
                    timestamp, formatted_message = message_data
                    text += f'{timestamp} {formatted_message}\n'
            self.update_message_text(text)
        else:
            self.update_message_text('No messages to display in the current channel.\n')
        self.update_user_list(channel)

    def display_message_in_chat(self, message):
        """
        Special method for showing nick changes, yellow.
        """
        def _append_message_to_chat():
            self.message_text.config(state=tk.NORMAL)
            self.message_text.insert(tk.END, message + "\n")
            self.message_text.config(state=tk.DISABLED)
            self.message_text.see(tk.END)
            
            # Apply a specific color (gold) for system messages (like nick changes)
            self.message_text.tag_configure("system_message", foreground="#FFD700")
            start_idx = self.message_text.search(message, "1.0", stopindex=tk.END)
            if start_idx:
                end_idx = f"{start_idx}+{len(message)}c"
                self.message_text.tag_add("system_message", start_idx, end_idx)

        self.root.after(0, _append_message_to_chat)

    def find_urls(self, text):
        # A simple regex to detect URLs
        url_pattern = re.compile(r'(\w+://\S+|www\.\S+)')
        return url_pattern.findall(text)

    def open_url(self, event, url):
        import webbrowser
        webbrowser.open(url)

    def find_channels(self, text):
        # A regex to detect channel names starting with #
        channel_pattern = re.compile(r'(?i)(#+[^\s,]+)(?![.:/])')
        return channel_pattern.findall(text)

    def join_channel(self, channel):
        if channel not in self.irc_client.joined_channels:
            # Add the channel to the irc_client's list of channels
            self.irc_client.joined_channels.append(channel)
        self.irc_client.send_message(f"JOIN {channel}")
        # Update the GUI's list of channels
        self.update_joined_channels_list(channel)

    def start(self):
        """
        It's Alive!
        """
        self.root.mainloop()
        while not self.exit_event.is_set():
            self.root.update()
            if self.exit_event.is_set():
                break
            time.sleep(0.1)
        self.irc_client.receive_thread.join()
        self.root.quit()


class ConfigWindow(tk.Toplevel):
    def __init__(self, current_config):
        super().__init__()
        self.title("Configuration")
        self.geometry("500x400")
        self.config_font = tkFont.Font(family="Hack", size=10)

        # Labels
        label_name = tk.Label(self, text="Nickname:", font=self.config_font)
        label_name.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        label_server = tk.Label(self, text="Server Address:", font=self.config_font)
        label_server.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

        label_channels = tk.Label(self, text="Auto-join Channels (comma-separated):", font=self.config_font)
        label_channels.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)

        label_password = tk.Label(self, text="Password:", font=self.config_font)
        label_password.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)

        label_port = tk.Label(self, text="Port:", font=self.config_font)
        label_port.grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)

        label_ssl = tk.Label(self, text="SSL Enabled:", font=self.config_font)
        label_ssl.grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)

        # Entry fields
        self.entry_name = tk.Entry(self)
        self.entry_name.grid(row=0, column=1, padx=5, pady=5)

        self.entry_server = tk.Entry(self)
        self.entry_server.grid(row=1, column=1, padx=5, pady=5)

        self.entry_channels = tk.Entry(self)
        self.entry_channels.grid(row=2, column=1, padx=5, pady=5)

        self.entry_password = tk.Entry(self, show="*")  # Mask the password with '*'
        self.entry_password.grid(row=3, column=1, padx=5, pady=5)

        self.entry_port = tk.Entry(self)
        self.entry_port.grid(row=4, column=1, padx=5, pady=5)

        self.entry_ssl = tk.BooleanVar()
        self.checkbox_ssl = tk.Checkbutton(self, variable=self.entry_ssl)
        self.checkbox_ssl.grid(row=5, column=1, padx=5, pady=5)

        # SASL Configuration
        label_sasl_enabled = tk.Label(self, text="SASL Enabled:", font=self.config_font)
        label_sasl_enabled.grid(row=8, column=0, padx=5, pady=5, sticky=tk.W)

        self.entry_sasl_enabled = tk.BooleanVar()
        self.checkbox_sasl_enabled = tk.Checkbutton(self, variable=self.entry_sasl_enabled)
        self.checkbox_sasl_enabled.grid(row=8, column=1, padx=5, pady=5)

        label_sasl_username = tk.Label(self, text="SASL Username:", font=self.config_font)
        label_sasl_username.grid(row=9, column=0, padx=5, pady=5, sticky=tk.W)

        self.entry_sasl_username = tk.Entry(self)
        self.entry_sasl_username.grid(row=9, column=1, padx=5, pady=5)

        label_sasl_password = tk.Label(self, text="SASL Password:", font=self.config_font)
        label_sasl_password.grid(row=10, column=0, padx=5, pady=5, sticky=tk.W)

        self.entry_sasl_password = tk.Entry(self, show="*")  # Mask the password with '*'
        self.entry_sasl_password.grid(row=10, column=1, padx=5, pady=5)

        # Font Selection
        label_font = tk.Label(self, text="Font:", font=self.config_font)
        label_font.grid(row=6, column=0, padx=5, pady=5, sticky=tk.W)

        self.font_var = tk.StringVar(self)
        self.font_var.set(self.config_font.actual()['family'])  #set the default font based on current font
        fonts = ["Monospace", "Consolas", "Liberation Mono", "DejaVu Sans Mono", "Hack"]
        font_dropdown = tk.OptionMenu(self, self.font_var, *fonts, command=self.update_font)
        font_dropdown.grid(row=6, column=1, padx=5, pady=5)

        # Font Size Selection
        label_font_size = tk.Label(self, text="Font Size:", font=self.config_font)
        label_font_size.grid(row=7, column=0, padx=5, pady=5, sticky=tk.W)

        self.font_size_var = tk.StringVar(self)
        default_size = str(current_config.get("font_size", 10))  # Default to 10 if not in config
        self.font_size_var.set(default_size)
        font_sizes = [str(i) for i in range(8, 21)]  # List of font sizes from 8 to 20
        font_size_dropdown = tk.OptionMenu(self, self.font_size_var, *font_sizes)
        font_size_dropdown.grid(row=7, column=1, padx=5, pady=5)

        # Save Button
        save_button = tk.Button(self, text="Save Configuration", command=self.save_config)
        save_button.grid(row=11, column=0, columnspan=2, padx=5, pady=5)

        # Set the current configuration values in the entry fields
        self.entry_name.insert(0, current_config["nickname"])
        self.entry_server.insert(0, current_config["server"])
        self.entry_channels.insert(0, (current_config["auto_join_channels"]))
        self.entry_password.insert(0, current_config["nickserv_password"])
        self.entry_port.insert(0, current_config["port"])
        self.entry_ssl.set(current_config["ssl_enabled"])
        self.entry_sasl_enabled.set(current_config.get("sasl_enabled", False))
        self.entry_sasl_username.insert(0, current_config.get("sasl_username", ""))
        self.entry_sasl_password.insert(0, current_config.get("sasl_password", ""))

    def update_font(self, font_choice):
        """Updates the font when the user selects a new font from the dropdown."""
        self.config_font.config(family=font_choice)
        for widget in self.winfo_children():
            if isinstance(widget, tk.Label):
                widget.config(font=self.config_font)

    def save_config(self):
        user_nick = self.entry_name.get()
        server_address = self.entry_server.get()
        channels = self.entry_channels.get()
        password = self.entry_password.get()
        port = self.entry_port.get()
        ssl_enabled = self.entry_ssl.get()
        # Get SASL configurations from the entry fields
        sasl_enabled = self.entry_sasl_enabled.get()
        sasl_username = self.entry_sasl_username.get()
        sasl_password = self.entry_sasl_password.get()


        # Create a new configparser object
        config = configparser.ConfigParser()

        # Update the configuration values directly
        config["IRC"] = {
            "nickname": user_nick,
            "server": server_address,
            "auto_join_channels": channels,
            "nickserv_password": password,
            "port": port,
            "ssl_enabled": ssl_enabled,
            "font_family": self.font_var.get(),
            "font_size": self.font_size_var.get(),
            "sasl_enabled": sasl_enabled,
            "sasl_username": sasl_username,
            "sasl_password": sasl_password
        }

        # Write the updated configuration to the conf.rude file
        # Get the directory of the current script
        script_directory = os.path.dirname(os.path.abspath(__file__))
        
        # Construct the full path for the conf.rude file
        config_file_path = os.path.join(script_directory, 'conf.rude')

        # Write the updated configuration to the conf.rude file using the full path
        with open(config_file_path, "w") as config_file:
            config.write(config_file)

        self.destroy()


class ChannelListWindow(tk.Toplevel):
    def __init__(self, file_path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Channel List")
        self.geometry("790x400")
        self.is_destroyed = False
        self.total_channels = 0

        self.create_widgets()
        self.start_download_thread(file_path)

    def create_widgets(self):
        self.tree = ttk.Treeview(self, columns=("Channel", "Users", "Topic"), show='headings')
        self.tree.heading("Channel", text="Channel")
        self.tree.heading("Users", text="Users")
        self.tree.heading("Topic", text="Topic")

        self.close_button = ttk.Button(self, text="Close", command=self.destroy)
        self.close_button.grid(row=1, column=0, columnspan=2, pady=10, padx=10, sticky="ew")

        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Progress bar
        self.progress_bar = ttk.Progressbar(self, orient="horizontal", mode="determinate")
        self.progress_bar.grid(row=2, column=0, columnspan=2, pady=10, padx=10, sticky="ew")

    def start_download_thread(self, file_path):
        self.total_channels = sum(1 for _ in open(file_path, 'r', encoding='utf-8'))
        download_thread = threading.Thread(target=self.read_and_insert_data, args=(file_path,), daemon=True)
        download_thread.start()

    def read_and_insert_data(self, file_path):
        processed_channels = 0
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, start=1):
                    parts = line.strip().split(", ")
                    if len(parts) < 3:
                        print(f"Skipping malformed line at Line {line_num}: {line}")
                        continue
                    try:
                        channel_name = parts[0].split(": ")[1]
                        user_count = parts[1].split(": ")[1]
                        topic = parts[2].split(": ")[1] if len(parts[2].split(": ")) > 1 else "No topic"
                        if channel_name == "*":
                            channel_name = "Hidden"
                    except Exception as e:
                        print(f"Error processing line {line_num} due to {e}: {line}")
                        continue

                    if not self.is_destroyed:
                        self.after(0, lambda cn=channel_name, uc=user_count, t=topic: self.tree.insert("", "end", values=(cn, uc, t)))
                        processed_channels += 1
                        progress = (processed_channels / self.total_channels) * 100
                        self.after(0, lambda p=progress: self.progress_bar.configure(value=p))
        except Exception as e:
            print(f"Error reading the file {file_path} due to {e}")

    def destroy(self):
        self.is_destroyed = True
        super().destroy()
        
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
