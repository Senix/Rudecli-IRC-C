"""
RudeCli-IRC-C: Rudimentary Command Line Interface IRC Client.
RudeCli assumes config.rude is available and configed properly:

Config Example:

[IRC]
server = irc.libera.chat
port = 6697
ssl_enabled = True
nickname = Rudie
nickserv_password = password
auto_join_channels = #irish

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
from queue import Queue


class IRCClient:
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

    def read_config(self, config_file):
        config = configparser.ConfigParser()
        config.read(config_file)

        self.server = config.get('IRC', 'server')
        self.port = config.getint('IRC', 'port')
        self.ssl_enabled = config.getboolean('IRC', 'ssl_enabled')
        self.nickname = config.get('IRC', 'nickname')
        self.nickserv_password = config.get('IRC', 'nickserv_password')
        self.auto_join_channels = config.get('IRC', 'auto_join_channels').split(',')

    def connect(self):
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

        self.irc.send(bytes(f'NICK {self.nickname}\r\n', 'UTF-8'))
        self.irc.send(bytes(f'USER {self.nickname} 0 * :{self.nickname}\r\n', 'UTF-8'))
        time.sleep(5)
        print(f'Connected to server: {self.server}:{self.port}')
        self.irc_client_gui.update_message_text(f'Connected to server: {self.server}:{self.port}\n')

        self.send_message(f'PRIVMSG NickServ :IDENTIFY {self.nickserv_password}')

        for channel in self.auto_join_channels:
            self.join_channel(channel)

    def send_message(self, message):
        if message == '/quit':
            self.irc.send(bytes(f'QUIT\r\n', 'UTF-8'))
        else:
            self.irc.send(bytes(f'{message}\r\n', 'UTF-8'))

            # Extract the target channel from the message
            target_match = re.match(r'PRIVMSG (\S+)', message)
            if target_match:
                target_channel = target_match.group(1)
                # Add the sent message to the channel history
                self.channel_messages.setdefault(target_channel, []).append((self.nickname, message))

            self.log_message(self.current_channel, self.nickname, message, is_sent=True)

    def join_channel(self, channel):
        self.send_message(f'JOIN {channel}')
        self.joined_channels.append(channel)
        self.channel_messages[channel] = []
        self.user_list[channel] = []
        print(f'Joined channel: {channel}')

    def leave_channel(self, channel):
        self.send_message(f'PART {channel}')
        if channel in self.joined_channels:
            self.joined_channels.remove(channel)
        if channel in self.channel_messages:
            del self.channel_messages[channel]
        print(f'Left channel: {channel}')
        if self.current_channel == channel:
            self.current_channel = ''

    def list_channels(self):
        self.send_message('LIST')

    def keep_alive(self):
        while True:
            time.sleep(195)
            param = self.server
            self.send_message(f'PING {param}')
            print(f'Sent Keep Alive: Ping')

    def sync_user_list(self):
        self.user_list[self.current_channel] =[]
        self.send_message(f'NAMES {self.current_channel}')

    def handle_incoming_message(self):
        while not self.exit_event.is_set():
            data = self.irc.recv(4096).decode('UTF-8', errors='ignore')
            if not data:
                break

            received_messages = ""

            messages = data.split('\r\n')

            self.server_feedback_buffer = ""

            for raw_message in messages:
                try:
                    if len(raw_message) == 0:
                        continue
                    tokens = irctokens.tokenise(raw_message)
                except ValueError as e:
                    print(f"Error: {e}")
                    continue

                if tokens.source is not None:
                    sender = tokens.hostmask.nickname
                else:
                    sender = None
                self.message_queue.put(raw_message)

                if tokens.command == "PING":
                    ping_param = tokens.params[0]
                    pong_response = f'PONG {ping_param}'
                    self.send_message(pong_response)
                    print(f'PING received: Response: PONG')

                elif tokens.command == "NOTICE" or tokens.command == "ERROR":
                    #process server feedback message
                    self.server_feedback_buffer += raw_message + "\n"
                    self.irc_client_gui.update_server_feedback_text(raw_message)

                elif tokens.command == "353":
                    channel = tokens.params[2]
                    users = tokens.params[3].split()

                    self.user_list[channel] = users
                    self.irc_client_gui.update_user_list(channel)

                elif tokens.command == "PART":
                    # Handle PART message to remove the user from the user list
                    if tokens.source is not None:
                        quit_user = tokens.hostmask.nickname
                        quit_message = tokens.params[0]
                        channel = tokens.params[0]
                        if channel in self.user_list and quit_user in self.user_list[channel]:
                            self.user_list[channel].remove(quit_user)
                            self.irc_client_gui.update_user_list(channel)
                    self.server_feedback_buffer += raw_message + "\n"
                    self.irc_client_gui.update_server_feedback_text(raw_message)

                elif tokens.command == "JOIN":
                    # Handle JOIN message to add the user to the user list
                    if tokens.source is not None:
                        join_user = tokens.hostmask.nickname
                        channel = tokens.params[0]
                        if channel in self.user_list:
                            if join_user not in self.user_list[channel]:
                                self.user_list[channel].append(join_user)
                                self.irc_client_gui.update_user_list(channel)
                        else:
                            self.user_list[channel] = [join_user]
                            self.irc_client_gui.update_user_list(channel)
                    self.server_feedback_buffer += raw_message + "\n"
                    self.irc_client_gui.update_server_feedback_text(raw_message)

                elif tokens.command == "QUIT":
                    # Handle QUIT message to remove the user from the user list
                    if tokens.source is not None:
                        quit_user = tokens.hostmask.nickname
                        quit_message = tokens.params[0]
                        for channel in self.user_list:
                            if quit_user in self.user_list[channel]:
                                self.user_list[channel].remove(quit_user)
                                self.irc_client_gui.update_user_list(channel)
                    self.server_feedback_buffer += raw_message + "\n"
                    self.irc_client_gui.update_server_feedback_text(raw_message)

                elif tokens.command == "PRIVMSG":
                    target = tokens.params[0]
                    message_content = tokens.params[1]

                    if message_content.startswith("\x01") and message_content.endswith("\x01"):
                        #CTCP request received
                        ctcp_command = message_content[1:-1]

                        if ctcp_command == "VERSION":
                            #respond to VERSION request
                            version_reply = "\x01VERSION RudeGUI-IRC-C v1.4\x01"
                            self.send_message(f'PRIVMSG {sender} :{version_reply}')
                        elif ctcp_command == "CTCP":
                            #respond to CTCP request
                            ctcp_response = "\x01CTCP response\x01"
                            self.send_message(f'PRIVMSG {sender} :{ctcp_response}')
                        elif ctcp_command == "TIME":
                            #respond to TIME request
                            time_reply = "\x01TIME " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\x01"
                            self.send_message(f'PRIVMSG {sender} :{time_reply}')
                        elif ctcp_command == "PING":
                            #respond to PING request
                            ping_reply = "\x01PING" + message_content[6:] + "\x01"
                            self.send_message(f'PRIVMSG {sender} :{ping_reply}')
                        else:
                            if message_content.startswith("\x01ACTION") and message_content.endswith("\x01"):
                                action_content = message_content[8:-1]
                                action_message = f'* {sender} {action_content}'
                                if target not in self.channel_messages:
                                    self.channel_messages[target] = []
                                self.channel_messages[target].append((sender, action_message))
                                if target == self.current_channel:
                                    received_messages += f'{action_message}\n'
                                else:
                                    self.notify_channel_activity(target)
                                self.log_message(target, sender, action_message, is_sent=False)
                            else:
                                if target not in self.channel_messages:
                                    self.channel_messages[target] = []
                                self.channel_messages[target].append((sender, message_content))
                                if target == self.current_channel:
                                    received_messages += f'<{sender}> {message_content}\n'
                                else:
                                    self.notify_channel_activity(target)

                        self.log_message(target, sender, message_content, is_sent=False)

                    else:
                        if target not in self.channel_messages:
                            self.channel_messages[target] = []
                        self.channel_messages[target].append((sender, message_content))
                        if target == self.current_channel:
                            received_messages += f'<{sender}> {message_content}\n'
                        else:
                            self.notify_channel_activity(target)

                else:
                    if raw_message.startswith(':'):
                        #move message starting with ":" to server feedback
                        self.server_feedback_buffer += raw_message + "\n"
                        self.irc_client_gui.update_server_feedback_text(raw_message)
                    else:
                        #print other messages in the main chat window
                        self.irc_client_gui.update_message_text(raw_message)

            if received_messages:
                #print(received_messages, end="", flush=True)
                self.message_queue.put(received_messages)
                self.irc_client_gui.update_message_text(received_messages)

    def log_message(self, channel, sender, message, is_sent=False):
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if is_sent:
            log_line = f'[{timestamp}] <{self.nickname}> {message}'
        else:
            log_line = f'[{timestamp}] <{sender}> {message}'
        directory = f'irc_log_{channel}'
        os.makedirs(directory, exist_ok=True)
        filename = f'{directory}/irc_log_{channel.replace("/", "_")}.txt'
        with open(filename, 'a') as file:
            file.write(log_line + '\n')

    def notify_channel_activity(self, channel):
        #print(f'Activity in channel {channel}!')
        #self.irc_client_gui.update_message_text(f'Activity in channel {channel}!\r\n')
        self.irc_client_gui.update_server_feedback_text(f'Activity in channel {channel}!\r')

    def start(self):
        self.connect()
        self.receive_thread = threading.Thread(target=self.handle_incoming_message)
        self.receive_thread.start()

        self.stay_alive_thread = threading.Thread(target=self.keep_alive)
        self.stay_alive_thread.start()

        self.gui_handler()
        self.exit_event.set()

    def gui_handler(self):
        while True:
            raw_message = self.message_queue.get()


class IRCClientGUI:
    def __init__(self, irc_client):
        self.irc_client = irc_client
        self.exit_event = irc_client.exit_event

        self.root = tk.Tk()
        self.root.title("RudeCLI-IRC-C")
        self.root.geometry("1000x600")
        #self.root.iconbitmap("favicon.ico")

        self.server_feedback_text = scrolledtext.ScrolledText(self.root, state=tk.DISABLED, bg="black", fg="#ff0000", height=5)
        self.server_feedback_text.grid(row=1, column=0, sticky="nsew", padx=1, pady=1)

        self.message_text = scrolledtext.ScrolledText(self.root, state=tk.DISABLED, bg="black", fg="#00ff00")
        self.message_text.grid(row=0, column=0, sticky="nsew", padx=1, pady=1)

        self.user_list_frame = tk.Frame(self.root, width=150, height=400, bg="black")
        self.user_list_frame.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=1, pady=1)

        self.user_list_label = tk.Label(self.user_list_frame, text="User List:", bg="black", fg="#FFA500")
        self.user_list_label.pack()

        self.user_list_text = scrolledtext.ScrolledText(self.user_list_frame, width=20, height=20, bg="black", fg="#FFA500")
        self.user_list_text.pack(fill=tk.BOTH, expand=True)

        self.joined_channels_label = tk.Label(self.user_list_frame, text="Channels:", bg="black", fg="#00bfff")
        self.joined_channels_label.pack()

        self.joined_channels_text = scrolledtext.ScrolledText(self.user_list_frame, width=20, height=20, bg="black", fg="#00bfff")
        self.joined_channels_text.pack(fill=tk.BOTH, expand=True)

        self.input_frame = tk.Frame(self.root)
        self.input_frame.grid(row=2, column=0, sticky="ew", padx=1, pady=1)

        self.nickname_label = tk.Label(self.input_frame, text=f" $ {self.irc_client.nickname} #> ")
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

        threading.Thread(target=self.irc_client.start).start()
        self.irc_client.irc_client_gui = self

        #bind a callback function to the channel list text widget
        self.joined_channels_text.bind("<Button-1>", self.switch_channel)

    def switch_channel(self, event):
        #get the selected channel from the clicked position
        index = self.joined_channels_text.index("@%d,%d" % (event.x, event.y))
        line_num = int(index.split(".")[0])
        channel = self.joined_channels_text.get(f"{line_num}.0", f"{line_num}.end").strip()

        if channel in self.irc_client.joined_channels:
            self.irc_client.current_channel = channel
            self.display_channel_messages()
            self.update_window_title(self.irc_client.nickname, channel)

    def handle_input(self, event):
        user_input = self.input_entry.get().strip()
        if user_input[0] == "/":
            self._command_parser(user_input, user_input[1:].split()[0])
        else:
            self.irc_client.send_message(f'PRIVMSG {self.irc_client.current_channel} :{user_input}')
            self.update_message_text(f'<{self.irc_client.nickname}> {user_input}\r\n')
        self.input_entry.delete(0, tk.END)

    def _command_parser(self, user_input:str, command: str):
        match command:
            case "quit":
                self.irc_client.send_message('QUIT')
            case "join":
                channel_name = user_input.split()[1]
                self.irc_client.join_channel(channel_name)
            case "part":
                channel_name = user_input.split()[1]
                self.irc_client.leave_channel(channel_name)
            case "ch":
                self.update_message_text(self.irc_client.joined_channels)
            case "sw":
                channel_name = user_input.split()[1]
                self.irc_client.current_channel = channel_name
                self.display_channel_messages()
                self.update_window_title(self.irc_client.nickname, channel_name)
            case "help":
                self.update_message_text(f'/join to join a channel\r\n')
                self.update_message_text(f'/part to leave a channel\r\n')
                self.update_message_text(f'/ch to list joined channels\r\n')
                self.update_message_text(f'/sw <channel> to switch to given channel\r\n')
                self.update_message_text(f'    -You can also click channels to switch\r\n')
                self.update_message_text(f'/messages to display any saved channel messages\r\n')
                self.update_message_text(f'/quit exits client\r\n')
            case "me":
                action_content = user_input.split(' ', 1)[1]
                action_message = f'\x01ACTION {action_content}\x01'
                self.irc_client.send_message(f'PRIVMSG {self.irc_client.current_channel} :{action_message}')
                self.update_message_text(f'* {self.irc_client.nickname} {action_content}\r\n')
            case "users":
                self.irc_client.sync_user_list()
            case _:
                self.update_message_text(f"Unkown Command! Type '/help' for help.\r\n")

    def update_server_feedback_text(self, message):
        self.server_feedback_text.config(state=tk.NORMAL)
        self.server_feedback_text.insert(tk.END, message + "\n", "server_feedback")
        self.server_feedback_text.config(state=tk.DISABLED)
        self.server_feedback_text.see(tk.END)

        #apply light blue text color to server feedback messages
        self.server_feedback_text.tag_configure("server_feedback", foreground="#0099FF") #make the server output blue because it's nice on the eyes.

    def update_user_list(self, channel):
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

        joined_channels_text = "\n".join(self.irc_client.joined_channels)
        self.joined_channels_text.config(state=tk.NORMAL)
        self.joined_channels_text.delete(1.0, tk.END)
        self.joined_channels_text.insert(tk.END, joined_channels_text)
        self.joined_channels_text.config(state=tk.DISABLED)

    def handle_exit(self):
        self.irc_client.exit_event.set()  
        self.irc_client.irc.shutdown(socket.SHUT_RDWR)
        self.root.destroy()

    def handle_tab_complete(self, event):
        #get the current input in the input entry field
        user_input = self.input_entry.get()
        cursor_pos = self.input_entry.index(tk.INSERT)

        #get the last word (partial nick) before the cursor
        match = re.search(r'\b\w+$', user_input[:cursor_pos])
        if match:
            partial_nick = match.group()
        else:
            return

        #get the user list for the current channel
        current_channel = self.irc_client.current_channel
        if current_channel in self.irc_client.user_list:
            user_list = self.irc_client.user_list[current_channel]
        else:
            return

        #remove @ and + symbols from nicknames
        user_list_cleaned = [nick.lstrip('@+') for nick in user_list]

        #find possible completions for the partial nick
        completions = [nick for nick in user_list_cleaned if nick.startswith(partial_nick)]

        if len(completions) == 1:
            #if there is a unique match, complete the nick
            completed_nick = completions[0]
            remaining_text = user_input[cursor_pos:]
            completed_text = user_input[:cursor_pos - len(partial_nick)] + completed_nick + remaining_text
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, completed_text)
        elif completions:
            #if there are multiple possible completions, display the common prefix
            common_prefix = os.path.commonprefix(completions)
            remaining_text = user_input[cursor_pos:]
            completed_text = user_input[:cursor_pos - len(partial_nick)] + common_prefix + remaining_text
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, completed_text)

        #prevent default behavior of the Tab key
        return 'break'

    def update_window_title(self, nickname, channel_name):
        title_parts = []
        if nickname:
            title_parts.append(nickname)
        if channel_name:
            title_parts.append(channel_name)
        if title_parts:
            self.root.title("RudeGUI-IRC-C - " + " | ".join(title_parts))
        else:
            self.root.title("RudeGUI-IRC-C")

        self.nickname_label.config(text=f"{channel_name} $ {nickname} $> ")

    def update_message_text(self, text):
        def _update_message_text():
            timestamp = datetime.datetime.now().strftime('[%H:%M:%S] ')
            self.message_text.config(state=tk.NORMAL)
            lines = text.split('\n')
            cleaned_lines = [line.rstrip('\r') for line in lines]  #remove trailing '\r' characters
            cleaned_text = '\n'.join(cleaned_lines)
            timestamped_text = timestamp + cleaned_text  #add timestamp to each line
            self.message_text.insert(tk.END, timestamped_text)
            self.message_text.config(state=tk.DISABLED)
            self.message_text.see(tk.END)

            #apply green text color<3
            self.message_text.tag_configure("brightgreen", foreground="#00ff00")
            self.message_text.tag_add("brightgreen", "1.0", "end")

        self.root.after(0, _update_message_text)

    def display_channel_messages(self):
        channel = self.irc_client.current_channel
        if channel in self.irc_client.channel_messages:
            messages = self.irc_client.channel_messages[channel]
            text = f'Messages in channel {channel}:\n'
            for sender, message in messages:
                if message.startswith(f'PRIVMSG {channel} :'):
                    message = message[len(f'PRIVMSG {channel} :'):]
                timestamp = datetime.datetime.now().strftime('[%H:%M:%S]')
                text += f'{timestamp} <{sender}> {message}\n'
            self.update_message_text(text)
        else:
            self.update_message_text('No messages to display in the current channel.')

        self.update_user_list(channel)

    def notify_channel_activity(self, channel):
        messagebox.showinfo('Channel Activity', f'There is new activity in channel {channel}!\r')

    def start(self):
        self.root.mainloop()
        while not self.exit_event.is_set():
            self.root.update()
            if self.exit_event.is_set():
                break
            time.sleep(0.1)
        self.irc_client.receive_thread.join()
        self.root.quit()

def main():
    """The Main Function for the RudeGUI IRC Client."""
    config_file = 'conf.rude'

    irc_client = IRCClient()
    irc_client.read_config(config_file)

    gui = IRCClientGUI(irc_client)
    gui.start()

if __name__ == '__main__':
    main()
