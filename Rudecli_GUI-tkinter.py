"""
RudeCli-IRC-C: Rudimentary Command Line Interface IRC Client.
RudeCli assumes config.rude is available and configed properly:

Config Example:

[IRC]
server = irc.libera.chat
port = 6697
ssl_enabled = True
nickname = Rudecli
nickserv_password = password

password can be replaced with your nicks password to auto-auth with nickserv.
to use ssl or not you can designate by port: no ssl: 6667 yes ssl: 6697
ssl_enabled = False needs port 6667
ssl_enabled = True needs port 6697(usually)

IRCClient class:
        It represents the IRC client and manages the connection, message handling, channel management, and user interactions.
        The constructor initializes various attributes such as joined_channels, current_channel, channel_messages, decoder, encoder, irc_client_gui, message_queue, and user_list.
        The read_config method reads the configuration settings from a file.
        The connect method establishes a connection with the IRC server and sends necessary registration commands.
        The send_message method sends a message to the IRC server or quits the client if the message is "/quit".
        The join_channel method sends a JOIN command to join a specified channel.
        The leave_channel method sends a PART command to leave a specified channel.
        The list_channels method sends a LIST command to request the list of available channels from the server.
        The keep_alive method sends periodic PING messages to keep the connection alive.
        The handle_incoming_message method handles incoming messages from the server, parses them, and performs the necessary actions based on the message type.
        The log_message method logs channel messages to files.
        The notify_channel_activity method notifies the user about activity in a specific channel.
        The start method is the main entry point of the IRC client. It establishes the connection, starts the message handling thread, keeps the client alive, and handles user inputs.

IRCClientGUI class:
        It represents the graphical user interface for the IRC client using Tkinter.
        The constructor initializes the GUI window and sets up the message display area, input entry, and other components.
        The handle_input method handles user input from the input entry, performs actions based on the input, and updates the GUI.
        The update_window_title method updates the window title based on the current nickname and channel.
        The update_message_text method updates the message display area with the provided text.
        The display_channel_messages method displays the stored messages for the current channel in the message display area.
        The notify_channel_activity method shows a message box to notify the user about activity in a specific channel.
        The start method starts the GUI main loop to handle events and keep the GUI running.

    Other functions and imports:
        The script imports various modules and libraries, such as ssl, socket, sys, threading, configparser, time, datetime, irctokens, re, os, tkinter, messagebox, scrolledtext, and tkinter.constants.
        The main block reads the configuration file, initializes an instance of IRCClient, creates an instance of IRCClientGUI, and starts the GUI.
"""


import ssl
import socket
import sys
import threading
import configparser
import time
import datetime
import irctokens
import re
import os
import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter.constants import *


class IRCClient:
    def __init__(self):
        self.joined_channels = []
        self.current_channel = ''
        self.channel_messages = {}  # Dictionary to store channel messages
        self.decoder = irctokens.StatefulDecoder()  # Create a StatefulDecoder instance
        self.encoder = irctokens.StatefulEncoder()  # Create a StatefulEncoder instance
        self.irc_client_gui = None  # Initialize the IRCClientGUI instance
        self.message_queue = []  # Message queue for storing messages
        self.user_list = {}

    def read_config(self, config_file):
        config = configparser.ConfigParser()
        config.read(config_file)

        self.server = config.get('IRC', 'server')
        self.port = config.getint('IRC', 'port')
        self.ssl_enabled = config.getboolean('IRC', 'ssl_enabled')
        self.nickname = config.get('IRC', 'nickname')
        self.nickserv_password = config.get('IRC', 'nickserv_password')  # Read NickServ password from the config file

    def connect(self):
        print(f'Connecting to server: {self.server}:{self.port}')

        if self.ssl_enabled:
            context = ssl.create_default_context()
            self.irc = context.wrap_socket(socket.socket(socket.AF_INET6 if ':' in self.server else socket.AF_INET),
                                           server_hostname=self.server)
        else:
            self.irc = socket.socket(socket.AF_INET6 if ':' in self.server else socket.AF_INET)

        self.irc.connect((self.server, self.port))

        # Send necessary IRC commands to register the client with the server
        self.irc.send(bytes(f'NICK {self.nickname}\r\n', 'UTF-8'))
        self.irc.send(bytes(f'USER {self.nickname} 0 * :{self.nickname}\r\n', 'UTF-8'))
        time.sleep(5)
        print(f'Connected to server: {self.server}:{self.port}')

        # Authenticate with NickServ using the stored password
        self.send_message(f'PRIVMSG NickServ :IDENTIFY {self.nickserv_password}')

    def send_message(self, message):
        if message == '/quit':
            self.irc.send(bytes(f'QUIT\r\n', 'UTF-8'))
            sys.exit(0)
        else:
            self.irc.send(bytes(f'{message}\r\n', 'UTF-8'))
            self.log_message(self.current_channel, self.nickname, message, is_sent=True)

    def join_channel(self, channel):
        self.send_message(f'JOIN {channel}')
        self.joined_channels.append(channel)
        self.channel_messages[channel] = []  # Initialize empty list for channel messages
        print(f'Joined channel: {channel}')

    def leave_channel(self, channel):
        self.send_message(f'PART {channel}')
        if channel in self.joined_channels:
            self.joined_channels.remove(channel)
        if channel in self.channel_messages:
            del self.channel_messages[channel]  # Remove channel messages
        print(f'Left channel: {channel}')
        if self.current_channel == channel:
            self.current_channel = ''

    def list_channels(self):
        self.send_message('LIST')

    def keep_alive(self):
        while True:
            time.sleep(500)
            param = self.server
            self.send_message(f'PING {param}')
            print(f'Sent Keep Alive: Ping')

    def handle_incoming_message(self):
        while True:
            data = self.irc.recv(4096).decode('UTF-8', errors='ignore')
            if not data:
                break

            received_messages = ""  # Variable to store multiple incoming messages

            # Split the received data into individual messages
            messages = data.split('\r\n')

            # Process each message
            for raw_message in messages:
                # Tokenize the incoming message
                try:
                    if len(raw_message) == 0:  # ignore empty lines.
                        continue
                    tokens = irctokens.tokenise(raw_message)
                except ValueError as e:
                    print(f"Error: {e}")
                    continue  # Skip command-less lines

                # Extract sender's nickname
                if tokens.source is not None:
                    sender = tokens.hostmask.nickname
                else:
                    sender = None

                # Handle specific commands
                if tokens.command == "PING":
                    # Respond with PONG (PNOG)
                    ping_param = tokens.params[0]
                    pong_response = f'PONG {ping_param}'
                    self.send_message(pong_response)
                    print(f'PING received: Response: PONG')
                elif tokens.command == "353":
                    # Update the user list with the received users
                    channel = tokens.params[2]
                    users = tokens.params[3].split()
                    if channel in self.user_list:
                        self.user_list[channel].extend(users)
                    else:
                        self.user_list[channel] = users
                elif tokens.command == "PRIVMSG":
                    target = tokens.params[0]
                    message_content = tokens.params[1]

                    # Check if it's an ACTION message
                    if message_content.startswith("\x01ACTION") and message_content.endswith("\x01"):
                        # Remove the CTCP ACTION tags and extract the action content
                        action_content = message_content[8:-1]
                        action_message = f'* {sender} {action_content}'
                        if target not in self.channel_messages:
                            self.channel_messages[target] = []
                        self.channel_messages[target].append((sender, action_message))
                        if target == self.current_channel:
                            received_messages += f'{action_message}\n'
                        else:
                            self.notify_channel_activity(target)  # Notify user about activity
                    else:
                        # Regular PRIVMSG message
                        if target not in self.channel_messages:
                            self.channel_messages[target] = []
                        self.channel_messages[target].append((sender, message_content))
                        if target == self.current_channel:
                            received_messages += f'<{sender}> {message_content}\n'
                        else:
                            self.notify_channel_activity(target)  # Notify user about activity

                    # Log the message
                    self.log_message(target, sender, message_content, is_sent=False)

                else:
                    # Server message
                    print(f': {raw_message}')
                    self.irc_client_gui.update_message_text(f'{raw_message}\r\n')

            if received_messages:
                print(received_messages, end="", flush=True)
                self.message_queue.append(received_messages)  # Append the received messages to the queue
                self.irc_client_gui.update_message_text(received_messages)

    def log_message(self, channel, sender, message, is_sent=False):
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if is_sent:
            log_line = f'[{timestamp}] <{self.nickname}> {message}'
        else:
            log_line = f'[{timestamp}] <{sender}> {message}'
        directory = f'irc_log_{channel}'
        os.makedirs(directory, exist_ok=True)  # Create directory if it doesn't exist
        filename = f'{directory}/irc_log_{channel.replace("/", "_")}.txt'
        with open(filename, 'a') as file:
            file.write(log_line + '\n')

    def notify_channel_activity(self, channel):
        print(f'Activity in channel {channel}!')
        self.irc_client_gui.update_message_text(f'Activity in channel {channel}!\r\n')

    def start(self):
        self.connect()
        receive_thread = threading.Thread(target=self.handle_incoming_message)
        receive_thread.start()

        # keep alive thread
        stay_alive = threading.Thread(target=self.keep_alive)
        stay_alive.start()

        while True:
            try:
                user_input = input(f'{self.current_channel}:<3 {self.nickname}: ')
                if user_input.startswith('/join'):
                    channel_name = user_input.split()[1]
                    self.join_channel(channel_name)
                elif user_input.startswith('/leave'):
                    channel_name = user_input.split()[1]
                    self.leave_channel(channel_name)
                elif user_input.startswith('/ch'):
                    print(f'{self.joined_channels}')
                elif user_input.startswith('/sw'):
                    channel_name = user_input.split()[1]
                    self.current_channel = channel_name
                    print(f'Switched to channel {self.current_channel}')
                    self.display_channel_messages()
                elif user_input.startswith('/messages'):
                    self.display_channel_messages()
                elif user_input.startswith('/quit'):
                    self.send_message('QUIT')
                    sys.exit(0)
                elif user_input.startswith('/help'):
                    print(f'/join to join a channel')
                    print(f'/leave to leave a channel')
                    print(f'/ch to list joined channels')
                    print(f'/sw <channel> to switch to given channel')
                    print(f'/messages to display any saved channel messages')
                    print(f'/quit exits client')
                elif self.current_channel:
                    self.send_message(f'PRIVMSG {self.current_channel} :{user_input}')
                    print(f'<{self.nickname}> {user_input}')
                else:
                    print('You are not in a channel. Use /join <channel> to join a channel.')

            except KeyboardInterrupt:
                self.send_message('QUIT')
                sys.exit(0)

    def display_channel_messages(self):
        if self.current_channel in self.channel_messages:
            messages = self.channel_messages[self.current_channel]
            print(f'Messages in channel {self.current_channel}:')
            for sender, message in messages:
                print(f'<{sender}> {message}')
        else:
            print('No messages to display in the current channel.')


class IRCClientGUI:
    def __init__(self, irc_client):
        self.irc_client = irc_client

        self.root = tk.Tk()
        self.root.title("RudeCLI-IRC-C")

        # Set the window size
        self.root.geometry("800x600")

        # Create and configure the text widget for displaying messages
        self.message_text = scrolledtext.ScrolledText(self.root, state=tk.DISABLED)
        self.message_text.pack(fill=tk.BOTH, expand=True)

        # Create the input entry and bind the Enter key to send messages
        self.input_frame = tk.Frame(self.root)
        self.input_frame.pack(fill=tk.X)

        # Create the nickname/channel label
        self.nickname_label = tk.Label(self.input_frame, text=f" $ {self.irc_client.nickname} <3")
        self.nickname_label.pack(side=tk.LEFT)

        # Create the input entry
        self.input_entry = tk.Entry(self.input_frame)
        self.input_entry.pack(fill=tk.X, expand=True)
        self.input_entry.bind("<Return>", self.handle_input)

        # Start the IRC client
        threading.Thread(target=self.irc_client.start).start()
        self.irc_client.irc_client_gui = self

    def handle_input(self, event):
        user_input = self.input_entry.get().strip()

        if user_input:
            if user_input.startswith('/quit'):
                self.irc_client.send_message('QUIT')
                self.root.quit()
            elif user_input.startswith('/join'):
                channel_name = user_input.split()[1]
                self.irc_client.join_channel(channel_name)
            elif user_input.startswith('/leave'):
                channel_name = user_input.split()[1]
                self.irc_client.leave_channel(channel_name)
                self.update_window_title(self.irc_client.nickname, '')  # Reset window title
            elif user_input.startswith('/ch'):
                self.update_message_text(self.irc_client.joined_channels)
            elif user_input.startswith('/sw'):
                channel_name = user_input.split()[1]
                self.irc_client.current_channel = channel_name
                self.display_channel_messages()
                self.update_window_title(self.irc_client.nickname, channel_name)  # Update window title and nickname label
            elif user_input.startswith('/help'):
                self.update_message_text(f'/join to join a channel\r\n')
                self.update_message_text(f'/leave to leave a channel\r\n')
                self.update_message_text(f'/ch to list joined channels\r\n')
                self.update_message_text(f'/sw <channel> to switch to given channel\r\n')
                self.update_message_text(f'/messages to display any saved channel messages\r\n')
                self.update_message_text(f'/quit exits client\r\n')
            elif user_input.startswith('/users'):
                self.update_message_text(f'{self.irc_client.user_list}\r')
            else:
                self.irc_client.send_message(f'PRIVMSG {self.irc_client.current_channel} :{user_input}')
                self.update_message_text(f'<{self.irc_client.nickname}> {user_input}\r\n')

        self.input_entry.delete(0, tk.END)

    def update_window_title(self, nickname, channel_name):
        title_parts = []
        if nickname:
            title_parts.append(nickname)
        if channel_name:
            title_parts.append(channel_name)
        if title_parts:
            self.root.title("RudeCLI-IRC-C - " + " | ".join(title_parts))
        else:
            self.root.title("RudeCLI-IRC-C")

        #update the nickname label
        self.nickname_label.config(text=f"{channel_name} $ {nickname} <3")

    def update_message_text(self, text):
        self.message_text.config(state=tk.NORMAL)
        self.message_text.insert(tk.END, text)
        self.message_text.config(state=tk.DISABLED)
        self.message_text.see(tk.END)

    def display_channel_messages(self):
        channel = self.irc_client.current_channel
        if channel in self.irc_client.channel_messages:
            messages = self.irc_client.channel_messages[channel]
            text = f'Messages in channel {channel}:\n'
            for sender, message in messages:
                text += f'<{sender}> {message}\n'
            self.update_message_text(text)
        else:
            self.update_message_text('No messages to display in the current channel.')


    def notify_channel_activity(self, channel):
        messagebox.showinfo('Channel Activity', f'There is new activity in channel {channel}!\r')

    def start(self):
        self.root.mainloop()


if __name__ == '__main__':
    config_file = 'conf.rude'

    irc_client = IRCClient()
    irc_client.read_config(config_file)

    gui = IRCClientGUI(irc_client)
    gui.start()