"""
RudeCli-IRC-C: Rudimentary Command Line Interface IRC Client.
RudeCli assumes config.rude is available and configed properly:

Config Example:

[IRC]
server = irc.libera.chat
port = 6697
ssl_enabled = True
nickname = Rudecli
nickserv_password = your_password_here

You can set your password if you use nickserv to auto-auth.
to use ssl or not you can designate by port: no ssl: 6667 yes ssl: 6697
ssl_enabled = False needs port 6667
ssl_enabled = True needs port 6697(usually)

    __init__(self): This is the constructor method that initializes the IRCClient object. It sets up instance variables for the joined channels, the current channel, and the channel messages.

    read_config(self, config_file): This method reads the IRC configuration from a specified config_file using the configparser module. It retrieves the server, port, and nickname from the configuration file and assigns them to the corresponding instance variables.

    connect(self): This method establishes a connection with the IRC server. It creates a socket, connects to the specified server and port, and sends the necessary IRC commands to register the client with the server.

    send_message(self, message): This method sends a message to the IRC server. It takes a message as a parameter, which is sent to the server over the established socket connection.

    join_channel(self, channel): This method joins a specified channel. It sends the JOIN command to the IRC server to join the channel, updates the joined_channels list and initializes an empty list in channel_messages to store messages for the joined channel.

    leave_channel(self, channel): This method leaves a specified channel. It sends the PART command to the IRC server to leave the channel, updates the joined_channels list, and removes the channel from the channel_messages dictionary.

    list_channels(self): This method sends a LIST command to the IRC server to retrieve a list of available channels.

    receive_messages(self): This method runs in a separate thread and continuously listens for incoming messages from the IRC server. It handles PING requests to keep the connection alive, processes PRIVMSG messages, stores them in the channel_messages dictionary, and prints received messages for the current channel. If an ERROR message is received, it sends a QUIT command to the server and exits the program.

    log_message(self, channel, sender, message, is_sent=False): This method logs a message to a file. It takes the channel, sender, and message as parameters and appends them to the respective channel's log file. If is_sent is set to True, it indicates that the message is sent by the client and includes the client's nickname in the log.

    start(self): This method is the main loop that handles user input. It initiates the connection, starts the receive_messages thread, and prompts the user for input. It processes various commands entered by the user, such as joining/leaving channels, switching channels, listing joined channels, displaying saved messages, and quitting the client.

    display_channel_messages(self): This method displays the messages for the current channel. It retrieves the messages from the channel_messages dictionary and prints them on the console.

    notify_channel_activity(self, channel): This method notifies the user of activity on a channel their currently not watching.
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

class IRCClient:
    def __init__(self):
        self.joined_channels = []
        self.current_channel = ''
        self.channel_messages = {}  # Dictionary to store channel messages
        self.decoder = irctokens.StatefulDecoder() # Create a StatefulDecoder instance
        self.encoder = irctokens.StatefulEncoder() # Create a StatefulEncoder instance

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
        self.irc.send(bytes(f'{message}\r\n', 'UTF-8'))

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
            time.sleep(190)
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
                    if len(raw_message) == 0: #ignore empty lines.
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

                else:
                    # Server message
                    print(f': {raw_message}')

            if received_messages:
                print(received_messages, end="", flush=True)
                received_messages = ""
                self.log_message(target, sender, message_content)

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

    def start(self,):
        self.connect()
        receive_thread = threading.Thread(target=self.handle_incoming_message)
        receive_thread.start()

        #keep alive thread
        stay_alive = threading.Thread(target=self.keep_alive)
        stay_alive.start()

        while True:
            try:
                user_input = input(f'{self.current_channel} $ {self.nickname} ε>')
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
                    self.log_message(self.current_channel, self.nickname, user_input, is_sent=True)
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

if __name__ == '__main__':
    config_file = 'conf.rude'

    irc_client = IRCClient()
    irc_client.read_config(config_file)
    irc_client.start()