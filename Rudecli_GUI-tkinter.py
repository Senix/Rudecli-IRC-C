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


import configparser
import datetime
import fnmatch
import irctokens
import os
import random
import re
import socket
import ssl
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkFont
from plyer import notification
from queue import Queue
from tkinter import messagebox, scrolledtext, Menu
from tkinter.constants import *


class IRCClient:
    MAX_MESSAGE_HISTORY_SIZE = 200
    def __init__(self):
        self.exit_event = threading.Event()
        self.joined_channels: list = []
        self.current_channel: str = ''
        self.channel_messages = {}
        self.decoder = irctokens.StatefulDecoder()
        self.encoder = irctokens.StatefulEncoder()
        self.irc_client_gui = None
        self.message_queue = Queue()
        self.user_list = {}
        self.receive_thread = None
        self.stay_alive_thread = None
        self.temp_user_list = {}
        self.backup_nicknames = ["Rudie", "stixie"]
        self.current_nick_index = 0
        self.ignore_list = []
        self.friend_list = []
        self.load_ignore_list()
        self.load_friend_list()
        self.user_dual_privileges = {}
        self.whois_data = {}
        self.user_list_lock = threading.Lock()
        self.has_auto_joined = False
        self.reconnection_thread = None
        self.dm_users = []
        self.dm_messages = {}
        self.sound_ctcp_count = 0
        self.sound_ctcp_limit = 5
        self.reset_timer = None
        self.sound_ctcp_limit_flag = False 
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

        # Send to server
        self.irc.send(bytes(f'{message}\r\n', 'UTF-8'))

        # Extract the target channel and actual message content from the message
        target_match = re.match(r'PRIVMSG (\S+) :(.+)', message)
        if target_match:
            target_channel = target_match.group(1)
            message_content = target_match.group(2).strip()

            # Add the sent message to the channel history
            if target_channel not in self.channel_messages:
                self.channel_messages[target_channel] = []

            # Only store the actual content of the message, not the entire command
            self.channel_messages[target_channel].append((timestamp, self.nickname, message_content))

            # If the target is a DM
            if target_channel not in self.joined_channels:
                if target_channel not in self.dm_messages:
                    self.dm_messages[target_channel] = []
                sent_dm = f"{timestamp} <{self.nickname}> {message_content}\n"
                self.dm_messages[target_channel].append(sent_dm)

            # Check if the message history size exceeds the maximum allowed
            if len(self.channel_messages[target_channel]) > self.MAX_MESSAGE_HISTORY_SIZE:
                # If the history exceeds the limit, remove the oldest messages to maintain the limit
                self.channel_messages[target_channel] = self.channel_messages[target_channel][-self.MAX_MESSAGE_HISTORY_SIZE:]

            # Log the message with the timestamp for display
            self.log_message(target_channel, self.nickname, message_content, is_sent=True)

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

                        case "353":
                            self.handle_353(tokens)

                        case "366":
                            self.handle_366(tokens)

                        case "311" | "312" | "313" | "317" | "319" | "301" | "671" | "338" | "318":
                            self.handle_whois_replies(tokens.command, tokens)

                        case "433":
                            self.handle_nickname_conflict(tokens)

                        case "PART":
                            self.handle_part_command(tokens, raw_message)

                        case "JOIN":
                            self.handle_join_command(tokens, raw_message)

                        case "QUIT":
                            self.handle_quit_command(tokens, raw_message)

                        case "NICK":
                            old_nickname = tokens.hostmask.nickname
                            new_nickname = tokens.params[0]
                            nick_change_message_content = f"{old_nickname} has changed their nickname to {new_nickname}"
                            
                            # Display the nick change message in the chat window
                            self.irc_client_gui.display_message_in_chat(nick_change_message_content)
                            self.irc_client_gui.update_user_list(channel)
                            self.irc_client_gui.update_server_feedback_text(raw_message)

                        case "MODE":
                            channel = tokens.params[0]
                            mode = tokens.params[1]
                            if len(tokens.params) > 2:  # Ensure there's a target user for the mode change
                                target_user = tokens.params[2]
                                self.handle_mode_changes(channel, mode, target_user)
                            self.irc_client_gui.update_server_feedback_text(raw_message)

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
        target = tokens.params[0]
        notice_content = tokens.params[1]
        
        # Check if the target is a channel or the user
        if target.startswith(("#", "&", "+", "!")):
            # This is a channel-specific NOTICE
            if target not in self.channel_messages:
                self.channel_messages[target] = []
            self.channel_messages[target].append((timestamp, sender, notice_content))
            if target == self.current_channel:
                return f'{timestamp} [NOTICE] <{sender}> {notice_content}'
            else:
                self.notify_channel_activity(target)
                return None
        else:
            # This is a user-specific NOTICE, display in a general "server" or "status" tab
            server_tab_content = f'[SERVER NOTICE] <{sender}> {notice_content}'
            self.irc_client_gui.update_server_feedback_text(server_tab_content)
            return None

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
                whois_response += "\n"
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
                    similar_users = [user for user in self.user_list[channel] if user == quit_user or user.startswith('@' + quit_user) or user.startswith('+' + quit_user)]
                    for user in similar_users:
                        self.user_list[channel].remove(user)
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
                        self.user_list[channel].append(join_user)  # Ensure the user is at the end of the list
                    self.irc_client_gui.update_user_list(channel)
                else:
                    self.user_list[channel] = [join_user]
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
                    self.irc_client_gui.update_user_list(channel)
        
        self.server_feedback_buffer += raw_message + "\n"
        self.irc_client_gui.update_server_feedback_text(raw_message)

    def handle_privmsg(self, tokens, timestamp):
        target = tokens.params[0]
        message_content = tokens.params[1]
        sender = tokens.hostmask.nickname  # Define the sender here
        received_messages = ""

        if target == self.nickname:
            # This is a DM
            if sender not in self.dm_users:
                self.dm_users.append(sender)

            received_dm = f"{timestamp} <{sender}> {message_content}\n"
            self.log_message(f"{sender}", sender, message_content)

            if sender not in self.dm_messages:
                self.dm_messages[sender] = []

            self.dm_messages[sender].append(received_dm)

            # Check if this DM is already in the channels_with_activity list
            dm_name = f"DM: {sender}"

            if dm_name not in self.irc_client_gui.channels_with_activity:
                self.irc_client_gui.channels_with_activity.append(dm_name)
                
            # Update the channels list in the GUI every time a DM is received
            self.irc_client_gui.update_joined_channels_list(dm_name) 

            # Only display the DM in the GUI if the currently selected channel is the DM from this sender
            if self.current_channel == sender:
                self.irc_client_gui.update_message_text(received_dm, sender=sender, is_dm=True)
        else:
            # This is a channel message
            self.log_message(target, sender, message_content, is_sent=False)

        if sender == self.nickname:
            return
        if self.should_ignore(sender):  # ignore based on hostmask
            return
        if sender in self.ignore_list:  # ignore based on nick
            return
        if self.nickname in message_content:
            self.trigger_beep_notification(channel_name=target, title="Ping", message="You've been pinged!")
            if target not in self.irc_client_gui.channels_with_mentions:
                self.irc_client_gui.channels_with_mentions.append(target)
                self.irc_client_gui.update_joined_channels_list(target)
        if target not in self.irc_client_gui.channels_with_activity:
            self.irc_client_gui.channels_with_activity.append(target)
            self.irc_client_gui.update_joined_channels_list(target)

        if message_content.startswith("\x01") and message_content.endswith("\x01"):
            received_message = self.handle_ctcp_request(sender, message_content)
            if received_message:
                if target not in self.channel_messages:
                    self.channel_messages[target] = []
                self.channel_messages[target].append((timestamp, sender, received_message))
                if target == self.current_channel:
                    received_messages += f'{timestamp} {received_message}\n'
        else:
            if target not in self.channel_messages:
                self.channel_messages[target] = []
            self.channel_messages[target].append((timestamp, sender, message_content))
            if target == self.current_channel:
                received_messages += f'{timestamp} <{sender}> {message_content}\n'

        return received_messages

    def handle_default_case(self, raw_message):
        if raw_message.startswith(':'):
            # move message starting with ":" to server feedback
            self.server_feedback_buffer += raw_message + "\n"
            self.irc_client_gui.update_server_feedback_text(raw_message)
        else:
            # print other messages in the main chat window
            self.irc_client_gui.update_message_text(raw_message)

    def handle_ctcp_request(self, sender, message_content):
        # Split the CTCP message content at the first space to separate the command from any data
        ctcp_parts = message_content[1:-1].split(" ", 1)
        ctcp_command = ctcp_parts[0]

        if ctcp_command == "VERSION":
            # Respond to VERSION request
            version_reply = "\x01VERSION IRishC 1.9\x01"
            self.send_message(f'NOTICE {sender} :{version_reply}')

        elif ctcp_command == "CTCP":
            # Respond to CTCP request
            ctcp_response = "\x01CTCP response\x01"
            self.send_message(f'NOTICE {sender} :{ctcp_response}')

        elif ctcp_command == "TIME":
            # Respond to TIME request
            time_reply = "\x01TIME " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\x01"
            self.send_message(f'NOTICE {sender} :{time_reply}')

        elif ctcp_command == "PING":
            if len(ctcp_parts) > 1:
                ping_data = ctcp_parts[1]
                ping_reply = "\x01PING " + ping_data + "\x01"
                print("Received CTCP PING request:", message_content)
                print("Sending CTCP PING reply:", ping_reply)
                self.send_message(f'NOTICE {sender} :{ping_reply}')
            else:
                print("Received PING CTCP request without timestamp/data.")

        elif ctcp_command == "FINGER":
            # Respond to FINGER request (customize as per requirement)
            version_data = "IRishC v1.9"
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
                print(f"Received SOUND CTCP: BEEP!")
                self.trigger_beep_notification()
            else:
                print("SOUND CTCP limit reached. Ignoring...")
                if not self.sound_ctcp_limit_flag:  # If the flag isn't set yet
                    self.sound_ctcp_limit_flag = True
                    self.start_reset_timer()
        else:
            if message_content.startswith("\x01ACTION") and message_content.endswith("\x01"):
                action_content = message_content[8:-1]
                action_message = f' * {sender} {action_content}'
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
        self.irc_client_gui.update_user_list(channel)

    def trigger_beep_notification(self, channel_name=None, title="Ping", message="You've been pinged!"):
        """
        You've been pinged! Plays a beep or noise on mention and shows a system notification
        """
        if channel_name:
            # Ensure channel_name is a string and replace problematic characters
            channel_name = str(channel_name).replace("#", "channel ")
            title = f"{title} from {channel_name}"

        if sys.platform.startswith("linux"):
            # Linux-specific notification sound using paplay
            sound_path = os.path.join(os.getcwd(), "Sounds", "Notification4.wav")
            os.system(f"paplay {sound_path}")
        elif sys.platform == "darwin":
            # macOS-specific notification sound using afplay
            os.system("afplay /System/Library/Sounds/Ping.aiff")
        elif sys.platform == "win32":
            # Windows-specific notification using winsound
            import winsound
            duration = 1000  # milliseconds
            frequency = 440  # Hz
            winsound.Beep(frequency, duration)
        else:
            # For other platforms, print a message
            print("Beep notification not supported on this platform.")

        try:
            # Desktop Notification
            notification.notify(
                title=title,
                message=message,
                timeout=5,  # seconds
            )
        except Exception as e:
            print(f"Desktop notification error: {e}")

    def sanitize_channel_name(self, channel):
        #gotta remove any characters that are not alphanumeric or allowed special characters
        return re.sub(r'[^\w\-\[\]{}^`|]', '_', channel)

    def log_message(self, channel, sender, message, is_sent=False):
        """
        Logs your chats for later use
        """
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if is_sent:
            log_line = f'[{timestamp}] <{self.nickname}> {message}'
        else:
            log_line = f'[{timestamp}] <{sender}> {message}'

        # Create a folder named "Logs" to store the logs
        logs_directory = 'Logs'
        os.makedirs(logs_directory, exist_ok=True)

        filename = f'{logs_directory}/irc_log_{self.sanitize_channel_name(channel)}.txt'
        with open(filename, 'a') as file:
            file.write(log_line + '\n')

    def save_friend_list(self):
        """
        save Friend list!
        """
        with open("friend_list.txt", "w") as f:
            for user in self.friend_list:
                f.write(f"{user}\n")

    def load_friend_list(self):
        """
        load Friend list!
        """
        if os.path.exists("friend_list.txt"):
            with open("friend_list.txt", "r") as f:
                self.friend_list = [line.strip() for line in f.readlines()]

    def save_ignore_list(self):
        """
        saves ignore list
        """
        with open("ignore_list.txt", "w") as f:
            for user in self.ignore_list:
                f.write(f"{user}\n")

    def load_ignore_list(self):
        """
        loads ignore list
        """
        if os.path.exists("ignore_list.txt"):
            with open("ignore_list.txt", "r") as f:
                self.ignore_list = [line.strip() for line in f.readlines()]

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
        self.irc_client = irc_client
        self.exit_event = irc_client.exit_event
        self.channels_with_mentions = []
        self.channels_with_activity = []
        self.nickname_colors = {}

        self.current_config = self.load_config()

        self.root = tk.Tk()
        self.root.title("RudeGUI-IRC-C")
        self.root.geometry("1200x600")
        self.icon_image = tk.PhotoImage(file=os.path.join(os.getcwd(), "rude.png"))
        self.root.iconphoto(True, self.icon_image)
        self.selected_channel = None
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        self.settings_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Settings", menu=self.settings_menu)
        self.settings_menu.add_command(label="Configure", command=self.open_config_window)

        default_font = self.current_config.get("font_family", "Liberation Mono")
        default_size = int(self.current_config.get("font_size", 10))
        self.chat_font = tkFont.Font(family=default_font, size=default_size)
        self.channel_user_list_font = tkFont.Font(family="DejaVu Sans Mono", size=9)
        self.server_font = tkFont.Font(family="DejaVu Sans Mono", size=9)

        self.server_feedback_text = scrolledtext.ScrolledText(self.root, state=tk.DISABLED, bg="black", fg="#ff0000", height=5, font=self.server_font)
        current_font = self.server_feedback_text.cget("font")
        self.server_feedback_text.tag_configure("bold", font=(current_font, 10, "bold"))  # Configure the bold tag 
        self.server_feedback_text.tag_configure("bold", font=(current_font, 10, "bold"))
        self.server_feedback_text.tag_configure("italic", font=(current_font, 10, "italic"))
        self.server_feedback_text.tag_configure("bold_italic", font=(current_font, 10, "bold italic"))
        self.server_feedback_text.grid(row=1, column=0, sticky="nsew", padx=1, pady=1)
        self.server_feedback_text.tag_configure("server_feedback", foreground="#7882ff")  # Configure tags

        self.message_text = scrolledtext.ScrolledText(self.root, state=tk.DISABLED, bg="black", fg="#ffffff", cursor="arrow", font=self.chat_font)
        self.message_text.grid(row=0, column=0, sticky="nsew", padx=1, pady=1)

        self.user_list_frame = tk.Frame(self.root, width=100, height=400, bg="black")
        self.user_list_frame.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=1, pady=1)

        self.user_list_label = tk.Label(self.user_list_frame, text="Users:", bg="black", fg="#39ff14")
        self.user_list_label.pack()

        self.user_list_text = scrolledtext.ScrolledText(self.user_list_frame, width=5, height=20, bg="black", fg="#39ff14", cursor="arrow", font=self.channel_user_list_font)
        self.user_list_text.pack(fill=tk.BOTH, expand=True)

        self.joined_channels_label = tk.Label(self.user_list_frame, text="Channels:", bg="black", fg="#00bfff")
        self.joined_channels_label.pack()

        self.joined_channels_text = scrolledtext.ScrolledText(self.user_list_frame, width=5, height=20, bg="black", fg="#ffffff", cursor="arrow", font=self.channel_user_list_font)
        self.joined_channels_text.pack(fill=tk.BOTH, expand=True)

        self.input_frame = tk.Frame(self.root)
        self.input_frame.grid(row=2, column=0, sticky="ew", padx=1, pady=1)

        self.nickname_label = tk.Label(self.input_frame, font=("Hack", 9, "italic"), text=f" $ {self.irc_client.nickname} #> ")
        self.nickname_label.pack(side=tk.LEFT)

        self.input_entry = tk.Entry(self.input_frame)
        self.input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.input_entry.bind("<Return>", self.handle_input)
        self.input_entry.bind("<Tab>", self.handle_tab_complete)

        self.exit_button = tk.Button(self.input_frame, text="Exit", command=self.handle_exit)
        self.exit_button.pack(side=tk.RIGHT)

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=3)
        self.root.grid_columnconfigure(1, weight=1)

        self.client_start_thread = threading.Thread(target=self.irc_client.start)
        self.client_start_thread.daemon = True 
        self.client_start_thread.start()
        self.irc_client.irc_client_gui = self

        #bind a callback function to the channel list text widget
        self.joined_channels_text.bind("<Button-1>", self.switch_channel)
        self.init_input_menu()

    def open_config_window(self):
        config_window = ConfigWindow(self.current_config)
        config_window.mainloop()

    def load_config(self):
        config = configparser.ConfigParser()
        config.read("conf.rude") 
        return dict(config["IRC"])  #convert config to a dictionary

    def switch_channel(self, event):
        # get the selected channel or DM from the clicked position
        index = self.joined_channels_text.index("@%d,%d" % (event.x, event.y))
        line_num = int(index.split(".")[0])
        selection = self.joined_channels_text.get(f"{line_num}.0", f"{line_num}.end").strip()

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
        return "#{:02x}{:02x}{:02x}".format(random.randint(0, 255), 
                                           random.randint(0, 255), 
                                           random.randint(0, 255))

    def handle_input(self, event):
        """
        This handles the user input, passes to command parser if needed.
        """
        user_input = self.input_entry.get().strip()
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
                self.input_entry.delete(0, tk.END)
            case "reconnect": #reconnects to network
                self.irc_client.reconnect()
                # Clear the input entry
                self.input_entry.delete(0, tk.END)
            case "connect": #connects to new network.
                server = args[1] if len(args) > 1 else None
                port = int(args[2]) if len(args) > 2 else None
                self.irc_client.reconnect(server, port)
                self.input_entry.delete(0, tk.END)
            case "join": #joing channel
                channel_name = user_input.split()[1]
                self.irc_client.join_channel(channel_name)
                self.input_entry.delete(0, tk.END)
            case "part": #part channel
                channel_name = user_input.split()[1]
                self.irc_client.leave_channel(channel_name)
                self.input_entry.delete(0, tk.END)
            case "query": #open a DM with a user
                target_user = user_input.split()[1] if len(user_input.split()) > 1 else None
                if not target_user:
                    self.update_message_text("Invalid usage. Usage: /query <nickname>\r\n")
                    return
                if target_user not in self.irc_client.dm_users:
                    self.irc_client.dm_users.append(target_user)
                    self.update_message_text(f"DM opened with {target_user}. Type your messages in the input box.\r\n")
                    self.update_joined_channels_list("DM: " + target_user) 
                else:
                    self.update_message_text(f"You already have a DM opened with {target_user}.\r\n")
                self.input_entry.delete(0, tk.END)
            case "msg": #send a message to a user
                parts = user_input.split(' ', 2)
                if len(parts) >= 3:
                    receiver = parts[1]
                    message_content = parts[2]
                    self.irc_client.send_message(f'PRIVMSG {receiver} :{message_content}')
                    self.update_message_text(f'<{self.irc_client.nickname} -> {receiver}> {message_content}\r\n')
                else:
                    self.update_message_text(f"Invalid usage. Usage: /msg <nickname> <message_content>\r\n")
                self.input_entry.delete(0, tk.END)
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
                self.input_entry.delete(0, tk.END)
            case "sw": #switch channels.
                channel_name = user_input.split()[1]
                self.irc_client.current_channel = channel_name
                self.display_channel_messages()
                self.update_window_title(self.irc_client.nickname, channel_name)
                self.input_entry.delete(0, tk.END)
            case "topic": #requests topic only for right now
                self.irc_client.send_message(f'TOPIC {self.irc_client.current_channel}')
                self.input_entry.delete(0, tk.END)
            case "help": #HELP!
                self.display_help()
                self.input_entry.delete(0, tk.END)
            case "users": #refreshes user list
                self.irc_client.sync_user_list()
                self.input_entry.delete(0, tk.END)
            case "nick": #changes nickname
                new_nickname = user_input.split()[1]
                self.irc_client.change_nickname(new_nickname)
                self.input_entry.delete(0, tk.END)
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
                self.input_entry.delete(0, tk.END)
            case "whois": #who is that?
                target = user_input.split()[1]
                self.irc_client.whois(target)
                self.input_entry.delete(0, tk.END)
            case "ping": #PNOG
                parts = user_input.split()
                target = parts[1] if len(parts) > 1 else None
                self.irc_client.ping_server(target)
                self.input_entry.delete(0, tk.END)
            case "clear": #Clears the screen
                self.clear_chat_window()
                self.input_entry.delete(0, tk.END)
            case "ignore": #ignores a user
                user_to_ignore = user_input.split()[1]
                if user_to_ignore:
                    if user_to_ignore not in self.irc_client.ignore_list:
                        self.irc_client.ignore_list.append(user_to_ignore)
                        self.update_message_text(f"You've ignored {user_to_ignore}.\r\n")
                    else:
                        self.update_message_text(f"{user_to_ignore} is already in your ignore list.\r\n")
                else:
                    self.update_message_text("Invalid usage. Usage: /ignore <nickname|hostmask>\r\n")
                self.input_entry.delete(0, tk.END)
            case "unignore": #unignores a user
                user_to_unignore = user_input.split()[1]
                if user_to_unignore in self.irc_client.ignore_list:
                    self.irc_client.ignore_list.remove(user_to_unignore)
                    self.update_message_text(f"You've unignored {user_to_unignore}.\r\n")
                else: 
                    self.update_message_text(f"{user_to_unignore} is not in your ignore list.\r\n")
                self.input_entry.delete(0, tk.END)
            case "sa": #sends to all channels
                message = ' '.join(user_input.split()[1:])
                for channel in self.irc_client.joined_channels:
                    self.irc_client.send_message(f'PRIVMSG {channel} :{message}')
                self.update_message_text(f'Message sent to all joined channels: {message}\r\n')
                self.input_entry.delete(0, tk.END)
            case "friend": #adds friend
                friend_name = user_input.split()[1]
                if friend_name not in self.irc_client.friend_list:
                    self.irc_client.friend_list.append(friend_name)
                    self.irc_client.save_friend_list()
                    self.update_message_text(f"{friend_name} added to friends.\r\n")
                else:
                    self.update_message_text(f"{friend_name} is already in your friend list.\r\n")
                self.input_entry.delete(0, tk.END)
            case "unfriend": #removes friend
                unfriend_name = user_input.split()[1]
                if unfriend_name in self.irc_client.friend_list:
                    self.irc_client.friend_list.remove(unfriend_name)
                    self.irc_client.save_friend_list()
                    self.update_message_text(f"{unfriend_name} removed from friends.\r\n")
                else:
                    self.update_message_text(f"{unfriend_name} is not in your friend list.\r\n")
                self.input_entry.delete(0, tk.END)
            case "CTCP":
                if len(args) < 3:
                    self.update_message_text("Invalid usage. Usage: /CTCP <nickname> <command> [parameters]\r\n")
                    return
                target = args[1]
                ctcp_command = args[2].upper()
                parameter = ' '.join(args[3:]) if len(args) > 3 else None
                self.irc_client.send_ctcp_request(target, ctcp_command, parameter)
                self.input_entry.delete(0, tk.END)
            case "rat": #rat
                self.input_entry.delete(0, tk.END)
                self.input_entry.insert(0, "~~,=,^>")
            case _:
                self.update_message_text(f"Unkown Command! Type '/help' for help.\r\n")

    def display_help(self):
        #general commands
        self.update_message_text("=== General Commands ===\r\n")
        self.update_message_text(f'/help - Display this help menu\r\n')
        self.update_message_text(f'/clear - Clear the chat window\r\n')
        self.update_message_text(f'/rat - To rat ~~,=,^>\r\n')
        self.update_message_text(f'Exit button - Send /quit and close client\r\n')
        self.update_message_text(f'Tab - Auto-complete nicknames\r\n')

        #connection related commands
        self.update_message_text("\r\n=== Connection Commands ===\r\n")
        self.update_message_text(f'/connect <server> <port> - Connect to a specific server\r\n')
        self.update_message_text(f'/disconnect - Disconnect from the server\r\n')
        self.update_message_text(f'/reconnect - Reconnect to the last server\r\n')
        self.update_message_text(f'/quit - Close connection and exit client\r\n')
        self.update_message_text(f'/ping - Ping the connected server or /ping <usernick> to ping a specific user\r\n')

        #channel and DM related commands
        self.update_message_text("\r\n=== Channel & DM Commands ===\r\n")
        self.update_message_text(f'/join <channel> - Join a channel\r\n')
        self.update_message_text(f'/part <channel> - Leave a channel\r\n')
        self.update_message_text(f'/sw <channel> - Switch to a given channel. Clicking on channels also switches\r\n')
        self.update_message_text(f'/sa - Send a message to all joined channels\r\n')
        self.update_message_text(f'/msg <nickname> <message> - Send a direct message, e.g., /msg NickServ IDENTIFY\r\n')
        self.update_message_text(f'/query <nickname> - Open a DM with a user\r\n')
        self.update_message_text(f'/cq <nickname> - Close the DM with a user\r\n')

        #user related commands
        self.update_message_text("\r\n=== User Commands ===\r\n")
        self.update_message_text(f'/whois <nickname> - Whois a specific user, e.g., /whois nickname\r\n')
        self.update_message_text(f'/ignore <nickname> & /unignore <nickname> - Ignore/Unignore a user\r\n')
        self.update_message_text(f'/friend <nickname> - Add a user to your friend list\r\n')
        self.update_message_text(f'/unfriend <nickname> - Remove a user from your friend list\r\n')

        #advanced commands
        self.update_message_text("\r\n=== Advanced Commands ===\r\n")
        self.update_message_text(f'/CTCP <nickname> <command> [parameters] - CTCP command, e.g., /CTCP Rudie CLIENTINFO\r\n')

    def format_message_for_display(self, message):
        """
        Processes an IRC message and applies bold and italic formatting for tkinter's Text widget.
        """
        
        # Remove color codes
        message = re.sub(r'\x03(\d{1,2}(,\d{1,2})?)?', '', message)
        formatted_message = ""
        bold_ranges = []  # List to keep track of the start and end positions for bold text
        italic_ranges = []  # List to keep track of the start and end positions for italic text
        bold_italic_ranges = []  # List to keep track of positions for combined bold and italic text
        
        in_bold = False
        in_italic = False
        start_bold = None
        start_italic = None
        
        for i, char in enumerate(message):
            if char == '\x02':  # ASCII for bold
                if in_bold:
                    bold_ranges.append((start_bold, i))
                    in_bold = False
                else:
                    start_bold = i
                    in_bold = True
            
            elif char == '\x1D':  # ASCII for italics
                if in_italic:
                    italic_ranges.append((start_italic, i))
                    in_italic = False
                else:
                    start_italic = i
                    in_italic = True
            
            elif char == '\x0F':  # ASCII for reset formatting
                if in_bold:
                    bold_ranges.append((start_bold, i))
                    in_bold = False
                if in_italic:
                    italic_ranges.append((start_italic, i))
                    in_italic = False
            
            if in_bold and in_italic:  # If both are active, it's bold-italic
                bold_italic_ranges.append((start_bold, i))
                start_bold = None
                start_italic = None
                in_bold = False
                in_italic = False
            
            # Add the character to the formatted message
            if char not in ['\x02', '\x1D', '\x0F']:
                formatted_message += char

        # If the message ends while still in bold or italic, add the final range
        if in_bold:
            bold_ranges.append((start_bold, len(formatted_message)))
        if in_italic:
            italic_ranges.append((start_italic, len(formatted_message)))

        return formatted_message, bold_ranges, italic_ranges, bold_italic_ranges

    def display_dm_messages(self, user):
        if user in self.irc_client.dm_messages:
            for message in self.irc_client.dm_messages[user]:
                self.update_message_text(message)

    def update_server_feedback_text(self, message):
        """
        This updates the server feedback, it takes into account ascii.
        """
        message = message.replace('\r', '')
        formatted_message, bold_ranges, italic_ranges, bold_italic_ranges = self.format_message_for_display(message)

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

    def update_user_list(self, channel):
        """
        This is responsible for updating the user list within the GUI.
        """
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

    def update_joined_channels_list(self, channel):
        """
        This handles all the fancy tags for channel notifications, mentions, etc.
        """
        # Create tags for highlighting
        self.joined_channels_text.tag_configure("selected", background="#2375b3")
        self.joined_channels_text.tag_configure("mentioned", background="red")
        self.joined_channels_text.tag_configure("activity", background="green")
        
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
        Tab complete! It's awesome.
        """
        # get the current input in the input entry field
        user_input = self.input_entry.get()
        cursor_pos = self.input_entry.index(tk.INSERT)

        # get the last word (partial nick) before the cursor
        match = re.search(r'\b\w+$', user_input[:cursor_pos])
        if match:
            partial_nick = match.group()
        else:
            return

        # get the user list for the current channel
        current_channel = self.irc_client.current_channel
        if current_channel in self.irc_client.user_list:
            user_list = self.irc_client.user_list[current_channel]
        else:
            return

        # remove @ and + symbols from nicknames
        user_list_cleaned = [nick.lstrip('@+') for nick in user_list]

        # find possible completions for the partial nick
        completions = [nick for nick in user_list_cleaned if nick.startswith(partial_nick)]

        if len(completions) == 1:
            # if there is a unique match, complete the nick
            completed_nick = completions[0] + ": "  # append ', ' to the nick
            remaining_text = user_input[cursor_pos:]
            completed_text = user_input[:cursor_pos - len(partial_nick)] + completed_nick + remaining_text
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, completed_text)
        elif completions:
            # if there are multiple possible completions, display the common prefix
            common_prefix = os.path.commonprefix(completions) + ", "  # append ', ' to the prefix
            remaining_text = user_input[cursor_pos:]
            completed_text = user_input[:cursor_pos - len(partial_nick)] + common_prefix + remaining_text
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, completed_text)

        # prevent default behavior of the Tab key
        return 'break'

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
            self.root.title("Rude GUI " + " | ".join(title_parts))
        else:
            self.root.title("Rude GUI ")

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
            
            self.message_text.insert(tk.END, cleaned_formatted_text)
            self.message_text.config(state=tk.DISABLED)
            self.message_text.see(tk.END)

            # Apply bold formatting
            self.message_text.tag_configure("bold", font=("Hack", 10, "bold"))
            for start, end in bold_ranges:
                start_idx = f"{start + 1}.0"
                end_idx = f"{end + 1}.0"
                self.message_text.tag_add("bold", start_idx, end_idx)

            # Apply italic formatting
            self.message_text.tag_configure("italic", font=("Hack", 10, "italic"))
            for start, end in italic_ranges:
                start_idx = f"{start + 1}.0"
                end_idx = f"{end + 1}.0"
                self.message_text.tag_add("italic", start_idx, end_idx)

            # Apply bold-italic formatting
            self.message_text.tag_configure("bold_italic", font=("Hack", 10, "bold italic"))
            for start, end in bold_italic_ranges:
                start_idx = f"{start + 1}.0"
                end_idx = f"{end + 1}.0"
                self.message_text.tag_add("bold_italic", start_idx, end_idx)

            # apply #C0FFEE text color
            self.message_text.tag_configure("brightgreen", foreground="#C0FFEE")
            self.message_text.tag_add("brightgreen", "1.0", "end")

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
                        nickname_color = "#00ff62"

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
                self.message_text.tag_configure("main_user_color", foreground="#00ff62")
                self.message_text.tag_add("main_user_color", start_idx, end_idx)
                start_idx = end_idx

                # Check if the start index has reached the end of the text
                if start_idx == tk.END:
                    break

            urls = self.find_urls(cleaned_formatted_text)
            for url in urls:
                # Mark found URLs in the text to avoid them being treated as channels
                cleaned_formatted_text = cleaned_formatted_text.replace(url, f"<URL>{url}</URL>")
                start_idx = self.message_text.search(url, "1.0", tk.END)
                if start_idx:
                    end_idx = f"{start_idx}+{len(url)}c"
                    self.message_text.tag_add("url", start_idx, end_idx)
                    self.message_text.tag_configure("url", foreground="blue", underline=1)
                    self.message_text.tag_bind("url", "<Button-1>", lambda e, url=url: self.open_url(url))

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
                        self.message_text.tag_add("channel", start_idx, end_idx)
                        self.message_text.tag_configure("channel", foreground="cyan", underline=1)
                        self.message_text.tag_bind("channel", "<Button-1>", lambda e, channel=channel: self.join_channel(channel))
                    
                    # Move the start index to after the current found channel to continue the search
                    start_idx = end_idx

        self.root.after(0, _update_message_text)

    def display_channel_messages(self):
        """
        This is responsible for showing the channels scrollback / history
        """
        channel = self.irc_client.current_channel
        if channel in self.irc_client.channel_messages:
            messages = self.irc_client.channel_messages[channel]
            text = ''
            for timestamp, sender, message in messages:
                if message.startswith(f'PRIVMSG {channel} :'):
                    message = message[len(f'PRIVMSG {channel} :'):]
                text += f'{timestamp} <{sender}> {message}\n'
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

    def show_input_menu(self, event):
        try:
            self.input_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.input_menu.grab_release()

    def cut_text(self):
        self.input_entry.event_generate("<<Cut>>")

    def copy_text(self):
        self.input_entry.event_generate("<<Copy>>")

    def paste_text(self):
        self.input_entry.event_generate("<<Paste>>")

    def select_all_text(self):
        self.input_entry.select_range(0, tk.END)
        self.input_entry.icursor(tk.END)

    def find_urls(self, text):
        # A simple regex to detect URLs
        url_pattern = re.compile(r'(\w+://\S+|www\.\S+)')
        return url_pattern.findall(text)

    def open_url(self, url):
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
        self.geometry("500x300")
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
        save_button.grid(row=8, column=0, columnspan=2, padx=5, pady=5)

        # Set the current configuration values in the entry fields
        self.entry_name.insert(0, current_config["nickname"])
        self.entry_server.insert(0, current_config["server"])
        self.entry_channels.insert(0, (current_config["auto_join_channels"]))
        self.entry_password.insert(0, current_config["nickserv_password"])
        self.entry_port.insert(0, current_config["port"])
        self.entry_ssl.set(current_config["ssl_enabled"])

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
            "font_size": self.font_size_var.get()
        }

        # Write the updated configuration to the conf.rude file
        with open("conf.rude", "w") as config_file:
            config.write(config_file)

        self.destroy()

def main():
    """The Main Function for the RudeGUI IRC Client."""
    config_file = 'conf.rude'

    irc_client = IRCClient()
    irc_client.read_config(config_file)

    gui = IRCClientGUI(irc_client)
    gui.start()

if __name__ == '__main__':
    main()
