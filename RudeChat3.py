import asyncio
import base64
import ssl
import configparser
import datetime
import irctokens
import random
import os
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

class AsyncIRCClient:
    def __init__(self, text_widget, server_text_widget, entry_widget, master, gui):
        self.master = master
        self.text_widget = text_widget
        self.entry_widget = entry_widget
        self.server_text_widget = server_text_widget
        self.joined_channels = []
        self.motd_lines = []
        self.current_channel = ''
        self.nickname = ''
        self.channel_messages = {}
        self.channel_users = {}
        self.user_modes = {}
        self.mode_to_symbol = {}
        self.decoder = irctokens.StatefulDecoder()
        self.encoder = irctokens.StatefulEncoder()
        self.gui = gui

    async def read_config(self, config_file):
        config = configparser.ConfigParser()
        config.read(config_file)
        self.server = config.get('IRC', 'server')
        self.port = config.getint('IRC', 'port')
        self.ssl_enabled = config.getboolean('IRC', 'ssl_enabled')
        self.nickname = config.get('IRC', 'nickname')
        self.nickserv_password = config.get('IRC', 'nickserv_password')  # Read NickServ password from the config file
        self.auto_join_channels = config.get('IRC', 'auto_join_channels').split(',')
        
        # Read new SASL-related fields
        self.sasl_enabled = config.getboolean('IRC', 'sasl_enabled', fallback=False)
        self.sasl_username = config.get('IRC', 'sasl_username', fallback=None)
        self.sasl_password = config.get('IRC', 'sasl_password', fallback=None)
        
        # Read server name from config file
        self.server_name = config.get('IRC', 'server_name', fallback=None)
        self.gui.update_nick_channel_label()

    async def connect(self):
        await self.connect_to_server()
        await self.send_initial_commands()
        await self.wait_for_welcome()

    async def connect_to_server(self):
        TIMEOUT = 400  # seconds
        self.text_widget.insert(tk.END, f'Connecting to server: {self.server}:{self.port}\r\n')
        self.gui.highlight_nickname()
        loop = asyncio.get_event_loop()
        if self.ssl_enabled:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            try:
                self.reader, self.writer = await asyncio.wait_for(
                    loop.create_connection(
                        lambda: asyncio.StreamReaderProtocol(asyncio.StreamReader(), loop=loop),
                        host=self.server, port=self.port, ssl=context),
                    timeout=TIMEOUT
                )
            except asyncio.TimeoutError:
                self.text_widget.insert(tk.END, "Connection timeout. Please try again later.\r\n")
        else:
            try:
                self.reader, self.writer = await asyncio.wait_for(
                    asyncio.open_connection(self.server, self.port),
                    timeout=TIMEOUT
                )
            except asyncio.TimeoutError:
                self.text_widget.insert(tk.END, "Connection timeout. Please try again later.\r\n")

    async def send_initial_commands(self):
        self.text_widget.insert(tk.END, f'Sent client registration commands.\r\n')
        await self.send_message(f'NICK {self.nickname}')
        await self.send_message(f'USER {self.nickname} 0 * :{self.nickname}')
        
        # Start capability negotiation
        if self.sasl_enabled:
            print("[DEBUG] About to send CAP LS 302")  # Debug message
            await self.send_message('CAP LS 302')
        else:
            print("[DEBUG] SASL is not enabled.")  # Debug message

        if self.nickserv_password:
            await self.send_message(f'PRIVMSG NickServ :IDENTIFY {self.nickserv_password}')
            
    async def wait_for_welcome(self):
        MAX_RETRIES = 5
        RETRY_DELAY = 5  # seconds
        retries = 0

        while retries < MAX_RETRIES:
            print(f"Retry count: {retries}")
            try:
                await self._await_welcome_message()
                return  # Successfully connected and received 001
            except (OSError, ConnectionError) as e:
                self.text_widget.insert(tk.END, f"Error occurred: {e}. Retrying in {RETRY_DELAY} seconds.\r\n")
                success = await self.reconnect()
                if success:
                    return  # Successfully reconnected
                retries += 1
                await asyncio.sleep(RETRY_DELAY)

        self.text_widget.insert(tk.END, "Failed to reconnect after multiple attempts. Please check your connection.\r\n")

    async def _await_welcome_message(self):
        self.text_widget.insert(tk.END, f'Waiting for welcome message from server.\r\n')
        buffer = ""
        received_001 = False  # Variable to track if 001 message has been received

        while True:
            data = await self.reader.read(4096)
            if not data:
                raise ConnectionError("Connection lost while waiting for welcome message.")
            
            decoded_data = data.decode('UTF-8', errors='ignore')
            buffer += decoded_data
            while '\r\n' in buffer:
                line, buffer = buffer.split('\r\n', 1)
                tokens = irctokens.tokenise(line)

                match tokens.command:
                    case "CAP":
                        await self.handle_cap(tokens)

                    case "AUTHENTICATE":
                        await self.handle_sasl_auth(tokens)

                    case "903":
                        await self.handle_sasl_successful()
                        sasl_authenticated = True

                    case "904":
                        await self.handle_sasl_failed()

                    case "001":
                        received_001 = True
                        self.text_widget.insert(tk.END, f'Connected to server: {self.server}:{self.port}\r\n')
                        received_001 = True  # Set this to True upon receiving 001
                        self.gui.insert_and_scroll()
                    case "005":  # Handling the ISUPPORT message
                        await self.handle_isupport(tokens)
                        self.gui.insert_and_scroll()
                    case "433":  # Nickname already in use
                        new_nickname = self.nickname + str(random.randint(1, 99))
                        await self.send_message(f'NICK {new_nickname}')
                        self.nickname = new_nickname
                        self.text_widget.insert(tk.END, f"Nickname already in use. Changed nickname to: {self.nickname}\r\n")
                    case "372":  # Individual line of MOTD
                        motd_line = tokens.params[-1]  # Assumes the MOTD line is the last parameter
                        self.motd_lines.append(motd_line)
                    case "376":  # End of MOTD
                        # Combine the individual MOTD lines into a single string
                        full_motd = "\n".join(self.motd_lines)
                        # Display the full MOTD, cleaned up
                        self.text_widget.insert(tk.END, f"Message of the Day:\n{full_motd}\r\n")
                        self.gui.insert_and_scroll()
                        # Clear the MOTD buffer for future use
                        self.motd_lines.clear()
                    case "PING":
                        ping_param = tokens.params[0]
                        await self.send_message(f'PONG {ping_param}')
                        self.gui.insert_and_scroll()
                    case _:
                        self.gui.insert_and_scroll()

            if received_001:
                # Auto-join channels
                for channel in self.auto_join_channels:
                    await self.join_channel(channel)
                    await asyncio.sleep(1)
                return  # Successfully connected and received 001

    async def handle_cap(self, tokens):
        print(f"[DEBUG] Handling CAP: {tokens.params}")
        if not self.sasl_enabled:
            print(f"[DEBUG] SASL is not enabled.")
            return  # Skip SASL if it's not enabled
        if "LS" in tokens.params:
            print(f"[DEBUG] Sending CAP REQ :sasl")
            await self.send_message("CAP REQ :sasl")
        elif "ACK" in tokens.params:
            print(f"[DEBUG] Sending AUTHENTICATE PLAIN")
            await self.send_message("AUTHENTICATE PLAIN")

    async def handle_sasl_auth(self, tokens):
        print(f"[DEBUG] Handling AUTHENTICATE: {tokens.params}")
        if not self.sasl_enabled:
            print(f"[DEBUG] SASL is not enabled.")
            return  # Skip SASL if it's not enabled
        if tokens.params[0] == '+':
            auth_string = f"{self.sasl_username}\0{self.sasl_username}\0{self.sasl_password}"
            encoded_auth_string = base64.b64encode(auth_string.encode()).decode()
            print(f"[DEBUG] Sending AUTHENTICATE {encoded_auth_string[:5]}...")  # Truncate to not reveal sensitive info
            await self.send_message(f"AUTHENTICATE {encoded_auth_string}")

    async def handle_sasl_successful(self):
        print(f"[DEBUG] SASL authentication successful.")
        if not self.sasl_enabled:
            print(f"[DEBUG] SASL is not enabled.")
            return  # Skip SASL if it's not enabled
        self.text_widget.insert(tk.END, f"SASL authentication successful.\r\n")
        await self.send_message("CAP END")

    async def handle_sasl_failed(self):
        print(f"[DEBUG] SASL authentication failed.")
        if not self.sasl_enabled:
            print(f"[DEBUG] SASL is not enabled.")
            return  # Skip SASL if it's not enabled
        self.text_widget.insert(tk.END, f"SASL authentication failed. Disconnecting.\r\n")

    async def send_message(self, message):
        self.writer.write(f'{message}\r\n'.encode('UTF-8'))
        await self.writer.drain()

    async def join_channel(self, channel):
        await self.send_message(f'JOIN {channel}')
        self.joined_channels.append(channel)
        self.gui.channel_lists[self.server] = self.joined_channels  # Update the GUI channel list
        self.update_gui_channel_list()  # Update the channel list in GUI

    async def leave_channel(self, channel):
        await self.send_message(f'PART {channel}')
        if channel in self.joined_channels:
            self.joined_channels.remove(channel)
        self.gui.channel_lists[self.server] = self.joined_channels  # Update the GUI channel list
        self.update_gui_channel_list()  # Update the channel list in GUI

    def update_gui_channel_list(self):
        self.gui.channel_listbox.delete(0, tk.END)  # Clear existing items
        for chan in self.joined_channels:
            self.gui.channel_listbox.insert(tk.END, chan)

    def update_gui_user_list(self, channel):
        print(f"Debug: channel_users = {self.channel_users}")  # Debug line
        self.gui.user_listbox.delete(0, tk.END)
        for user in self.channel_users.get(channel, []):
            self.gui.user_listbox.insert(tk.END, user)

    async def reconnect(self):
        self.text_widget.insert(tk.END, f'Connection lost. Attempting to reconnect...\r\n')
        MAX_RETRIES = 5
        retries = 0
        while retries < MAX_RETRIES:
            try:
                await self.connect()
                self.text_widget.insert(tk.END, f'Successfully reconnected.\r\n')
                return True  # Successfully reconnected
            except Exception as e:
                retries += 1
                self.text_widget.insert(tk.END, f'Failed to reconnect ({retries}/{MAX_RETRIES}): {e}. Retrying in {RETRY_DELAY} seconds.\r\n')
                await asyncio.sleep(RETRY_DELAY)
        return False  # Failed to reconnect after MAX_RETRIES

    async def keep_alive(self):
        while True:
            try:
                await asyncio.sleep(194)
                await self.send_message(f'PING {self.server}')
            except ConnectionResetError:
                await self.reconnect()

    async def handle_server_message(self, line):
        self.server_text_widget.insert(tk.END, f"{line}\r\n")
        self.gui.insert_and_scroll()

    async def handle_notice_message(self, tokens):
        sender = tokens.hostmask if tokens.hostmask else "Server"
        target = tokens.params[0]
        message = tokens.params[1]
        self.server_text_widget.insert(tk.END, f"NOTICE {sender}: {message}\r\n")
        self.gui.insert_and_scroll()

    async def handle_ctcp(self, tokens):
        timestamp = datetime.datetime.now().strftime('[%H:%M:%S] ')
        sender = tokens.hostmask.nickname
        target = tokens.params[0]
        message = tokens.params[1]

        # Detect if this is a CTCP message
        if message.startswith('\x01') and message.endswith('\x01'):
            ctcp_command = message[1:-1].split(' ', 1)[0]  # Extract the CTCP command
            ctcp_content = message[1:-1].split(' ', 1)[1] if ' ' in message else None  # Extract the content if present

            match ctcp_command:
                case "VERSION":
                    if tokens.command == "PRIVMSG":
                        await self.send_message(f'NOTICE {sender} :\x01VERSION RudeChat3.0\x01')
                case "PING":
                    if tokens.command == "PRIVMSG":
                        await self.send_message(f'NOTICE {sender} :\x01PING {ctcp_content}\x01')
                case "TIME":
                    if tokens.command == "PRIVMSG":
                        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        await self.send_message(f'NOTICE {sender} :\x01TIME {current_time}\x01')
                case "ACTION":
                    action_message = f"{timestamp}* {sender} {ctcp_content}"
                    self.text_widget.insert(tk.END, action_message)
                    self.gui.highlight_nickname()
                case _:
                    print(f"Unhandled CTCP command: {ctcp_command}")

    def notify_user_of_mention(self, server, channel):
        notification_msg = f"Mention on {server} in {channel}"
        self.text_widget.insert(tk.END, f"\n{notification_msg}\n")
        self.gui.insert_and_scroll()

        # Highlight the mentioned channel in the Listbox
        for idx in range(self.gui.channel_listbox.size()):
            if self.gui.channel_listbox.get(idx) == channel:
                self.gui.channel_listbox.itemconfig(idx, {'bg':'red'})
                break

    async def handle_privmsg(self, tokens):
        timestamp = datetime.datetime.now().strftime('[%H:%M:%S] ')
        sender = tokens.hostmask.nickname
        target = tokens.params[0]
        message = tokens.params[1]

        # Check if the user is mentioned in the message
        if self.nickname in message:
            self.notify_user_of_mention(self.server, target)

        # Check for CTCP command
        if message.startswith('\x01') and message.endswith('\x01'):
            await self.handle_ctcp(tokens)
            return

        # If the target is the bot's nickname, it's a DM
        if target == self.nickname:
            target = sender  # Consider the sender as the "channel" for DMs

        # Check if the "channel" (could be an actual channel or a DM) exists in the dictionary
        if target not in self.channel_messages:
            self.channel_messages[target] = []

            # If it's a DM and not in the joined_channels list, add it
            if target == sender and target not in self.joined_channels:
                self.joined_channels.append(target)
                self.gui.channel_lists[self.server] = self.joined_channels
                self.update_gui_channel_list()

        # Now it's safe to append the message
        self.channel_messages[target].append(f"{timestamp}<{sender}> {message}\r\n")

        # Trim the messages list if it exceeds 200 lines
        if len(self.channel_messages[target]) > 200:
            self.channel_messages[target] = self.channel_messages[target][-200:]

        # Display the message in the text_widget if the target matches the current channel or DM
        if target == self.current_channel and self.gui.irc_client == self:
            self.text_widget.insert(tk.END, f"{timestamp}<{sender}> {message}\r\n")
            self.gui.highlight_nickname()
            self.gui.insert_and_scroll()
        else:
            # If it's not the currently viewed channel, highlight the channel in green in the Listbox
            for idx in range(self.gui.channel_listbox.size()):
                if self.gui.channel_listbox.get(idx) == target:
                    current_bg = self.gui.channel_listbox.itemcget(idx, 'bg')
                    if current_bg != 'red':
                        self.gui.channel_listbox.itemconfig(idx, {'bg':'green'})
                    break

    async def handle_join(self, tokens):
        user_info = tokens.hostmask.nickname
        channel = tokens.params[0]
        self.text_widget.insert(tk.END, f"{user_info} has joined channel {channel}\r\n")

        # If the user joining is the client's user, just return
        if user_info == self.nickname:
            return

        # Check if the user is not already in the channel_users list for the channel
        if user_info not in self.channel_users.get(channel, []):
            # Add the user to the channel_users list
            self.channel_users.setdefault(channel, []).append(user_info)
        else:
            self.text_widget.insert(tk.END, f"{user_info} is already in the user list for channel {channel}\r\n")

        # Sort the user list for the channel
        sorted_users = self.sort_users(self.channel_users[channel], channel)

        # Update the user listbox for the channel with sorted users
        self.update_user_listbox(channel)

    async def handle_part(self, tokens):
        user_info = tokens.hostmask.nickname  # No "@" symbol
        channel = tokens.params[0]
        self.text_widget.insert(tk.END, f"{user_info} has parted from channel {channel}\r\n")

        # Check if the user is in the channel_users list for the channel
        user_found = False
        for user_with_symbol in self.channel_users.get(channel, []):
            # Check if the stripped user matches user_info
            if user_with_symbol.lstrip('@+%') == user_info:
                user_found = True
                self.channel_users[channel].remove(user_with_symbol)
                break

        if user_found:
            # Update the user listbox for the channel
            self.update_user_listbox(channel)
        else:
            pass

    async def handle_quit(self, tokens):
        user_info = tokens.hostmask.nickname  # No stripping needed here
        reason = tokens.params[0] if tokens.params else "No reason"
        self.text_widget.insert(tk.END, f"{user_info} has quit: {reason}\r\n")

        # Remove the user from all channel_users lists
        for channel in self.channel_users:
            # Check if the user is in the channel_users list for the channel
            user_found = False
            for user_with_symbol in self.channel_users.get(channel, []):
                # Check if the stripped user matches user_info
                if user_with_symbol.lstrip('@+%') == user_info:
                    user_found = True
                    self.channel_users[channel].remove(user_with_symbol)
                    break

            if user_found:
                # Update the user listbox for the channel
                self.update_user_listbox(channel)
            else:
                pass

    async def handle_nick(self, tokens):
        old_nick = tokens.hostmask.nickname  # No stripping here, we will handle it in the loop
        new_nick = tokens.params[0]
        self.text_widget.insert(tk.END, f"{old_nick} has changed their nickname to {new_nick}\r\n")

        # Update the user's nick in all channel_users lists they are part of
        for channel, users in self.channel_users.items():
            for idx, user_with_symbol in enumerate(users):
                # Check if the stripped user matches old_nick
                if user_with_symbol.lstrip('@+%') == old_nick:
                    # Extract the mode symbols from the old nickname
                    mode_symbols = ''.join([c for c in user_with_symbol if c in '@+%'])
                    
                    # Replace old_nick with new_nick, retaining the mode symbols
                    users[idx] = mode_symbols + new_nick
                    
                    # Update the user listbox for the channel if necessary
                    self.update_user_listbox(channel)
                    break

    def sort_users(self, users, channel):
        sorted_users = []
        current_modes = self.user_modes.get(channel, {})

        raw_users = []
        for user_with_possible_mode in users:
            detected_modes = set()
            for mode, symbol in self.mode_to_symbol.items():
                if user_with_possible_mode.startswith(symbol):
                    detected_modes.add(mode)
                    user_with_possible_mode = user_with_possible_mode[len(symbol):]

            # Update the user's modes in the current_modes dictionary
            if detected_modes:
                if user_with_possible_mode in current_modes:
                    current_modes[user_with_possible_mode].update(detected_modes)
                else:
                    current_modes[user_with_possible_mode] = detected_modes

            raw_users.append(user_with_possible_mode)

        # Now, for each raw user, apply the highest-priority mode
        mode_priority = list(self.mode_to_symbol.keys())
        for user in raw_users:
            modes = current_modes.get(user, set())

            # Pick the highest priority mode for the user
            chosen_mode = None
            for priority_mode in mode_priority:
                if priority_mode in modes:
                    chosen_mode = priority_mode
                    break

            mode_symbol = self.mode_to_symbol.get(chosen_mode, "")
            sorted_users.append(f"{mode_symbol}{user}")

        # Sort the user list based on the mode symbols
        sorted_users = sorted(
            sorted_users,
            key=lambda x: (mode_priority.index(next((m for m, s in self.mode_to_symbol.items() if s == x[0]), None)) if x[0] in self.mode_to_symbol.values() else len(mode_priority), x)
        )

        # Update the user modes dictionary and the channel_users list
        self.user_modes[channel] = current_modes
        self.channel_users[channel] = sorted_users
        return sorted_users

    async def handle_mode(self, tokens):
        channel = tokens.params[0]
        mode_change = tokens.params[1]
        user = tokens.params[2] if len(tokens.params) > 2 else None

        if channel in self.joined_channels and user:
            current_modes = self.user_modes.get(channel, {})

            # Handle addition of modes
            if mode_change.startswith('+'):
                mode = mode_change[1]
                current_modes.setdefault(user, set()).add(mode)
                    
            # Handle removal of modes
            elif mode_change.startswith('-'):
                mode = mode_change[1]
                user_modes = current_modes.get(user, set())
                user_modes.discard(mode)
                
                # Remove the mode symbols from the channel_users list
                symbol_to_remove = self.mode_to_symbol[mode]
                self.channel_users[channel] = [u.replace(symbol_to_remove, '') if u.endswith(user) else u for u in self.channel_users.get(channel, [])]
                
                if not user_modes:
                    del current_modes[user]  # Remove the user's entry if no modes left
                else:
                    current_modes[user] = user_modes  # Update the user's modes

            self.user_modes[channel] = current_modes

            # Update the user list to reflect the new modes
            sorted_users = self.sort_users(self.channel_users.get(channel, []), channel)
            self.channel_users[channel] = sorted_users

            self.update_user_listbox(channel)

    def update_user_listbox(self, channel):
        current_users = self.channel_users.get(channel, [])
        sorted_users = self.sort_users(current_users, channel)
        
        # Only update the user listbox if the channel is the currently selected channel
        if channel == self.current_channel:
            # Update the Tkinter Listbox to reflect the current users in the channel
            self.gui.user_listbox.delete(0, tk.END)  # Clear existing items
            for user in sorted_users:
                self.gui.user_listbox.insert(tk.END, user)
                       
    async def handle_isupport(self, tokens):
        params = tokens.params[:-1]  # Exclude the trailing "are supported by this server" message
        isupport_message = " ".join(params)
        self.server_text_widget.insert(tk.END, f"ISUPPORT: {isupport_message}\r\n")
        self.gui.insert_and_scroll()

        # Parse PREFIX for mode-to-symbol mapping
        for param in params:
            if param.startswith("PREFIX="):
                _, mappings = param.split("=")
                modes, symbols = mappings[1:].split(")")
                self.mode_to_symbol = dict(zip(modes, symbols))

    async def handle_incoming_message(self):
        buffer = ""
        current_users_list = []
        current_channel = ""
        while True:
            try:
                data = await self.reader.read(4096)
            except OSError as xe:
                if xe.errno == 121:  # The semaphore timeout period has expired
                    self.text_widget.insert(tk.END, f"WinError: {xe}") 
                    continue  # Attempt to read again
                else:
                    raise

            if not data:
                break

            decoded_data = data.decode('UTF-8', errors='ignore')
            buffer += decoded_data

            while '\r\n' in buffer:
                line, buffer = buffer.split('\r\n', 1)
                try:
                    # Check for an empty line or line with only whitespace before attempting to tokenize
                    if len(line.strip()) == 0:
                        self.text_widget.insert(tk.END, f"Received an empty or whitespace-only line: '{line}'\r\n")
                        continue

                    # Additional check: Ensure that the line has at least one character
                    if len(line) < 1:
                        self.text_widget.insert(tk.END, f"Received a too-short line: '{line}'\r\n")
                        continue

                    # Debug statement to print the line before tokenizing
                    print(f"Debug: About to tokenize the line - '{line}'")

                    tokens = irctokens.tokenise(line)
                except ValueError as e:
                    self.text_widget.insert(tk.END, f"Error: {e}\r\n")
                    continue
                except IndexError as ie:
                    self.text_widget.insert(tk.END, f"IndexError: {ie}. Line: '{line}'\r\n")
                    continue

                match tokens.command:
                    case "353":  # NAMES list
                        current_channel = tokens.params[2]
                        users = tokens.params[3].split(" ")
                        
                        # If this channel isn't in channel_users, initialize it with an empty list
                        if current_channel not in self.channel_users:
                            self.channel_users[current_channel] = []
                            
                        # Append the users to the channel's list only if they are not already in it
                        for user in users:
                            if user not in self.channel_users[current_channel]:
                                self.channel_users[current_channel].append(user)
                                
                    case "366":  # End of NAMES list
                        if current_channel:
                            # Sort the entire list of users for the channel
                            sorted_users = self.sort_users(self.channel_users[current_channel], current_channel)
                            self.channel_users[current_channel] = sorted_users
                            self.update_user_listbox(current_channel)  # Pass current_channel here
                            current_channel = ""

                    case "372":  # Individual line of MOTD
                        motd_line = tokens.params[-1]  # Assumes the MOTD line is the last parameter
                        self.motd_lines.append(motd_line)
                    
                    case "376":  # End of MOTD
                        # Combine the individual MOTD lines into a single string
                        full_motd = "\n".join(self.motd_lines)
                        # Display the full MOTD, cleaned up
                        self.text_widget.insert(tk.END, f"Message of the Day:\n{full_motd}\r\n")
                        self.gui.insert_and_scroll()
                        # Clear the MOTD buffer for future use
                        self.motd_lines.clear()

                    case "NOTICE":
                        await self.handle_notice_message(tokens)
                    case "PRIVMSG":
                        await self.handle_privmsg(tokens)
                    case "JOIN":
                        await self.handle_join(tokens)
                    case "PART":
                        await self.handle_part(tokens)
                    case "QUIT":
                        await self.handle_quit(tokens)
                    case "NICK":
                        await self.handle_nick(tokens)
                    case "MODE":
                        await self.handle_mode(tokens)
                    case "PING":
                        ping_param = tokens.params[0]
                        await self.send_message(f'PONG {ping_param}')
                        print(f"sent PONG: {ping_param}")
                    case "PONG":
                        pong_server = tokens.params[-1]  # Assumes the server name is the last parameter
                        self.server_text_widget.insert(tk.END, f"PNOG: {pong_server}\r\n")
                        self.gui.insert_and_scroll()
                    case _:
                        print(f"Debug: Unhandled command {tokens.command}. Full line: {line}")
                        if line.startswith(f":{self.server}"):
                            await self.handle_server_message(line)

    async def command_parser(self, user_input):
        args = user_input[1:].split() if user_input.startswith('/') else []
        primary_command = args[0] if args else None

        timestamp = datetime.datetime.now().strftime('[%H:%M:%S] ')

        match primary_command:
            case "join":
                channel_name = args[1]
                await self.join_channel(channel_name)

            case "part":
                channel_name = args[1]
                await self.leave_channel(channel_name)

            case "me":
                if self.current_channel:
                    await self.handle_action(args)
                else:
                    self.text_widget.insert(tk.END, "No channel selected. Use /join to join a channel.\r\n")

            case "ch":
                for channel in self.joined_channels:
                    self.text_widget.insert(tk.END, f'{channel}\r\n')

            case "sw":
                channel_name = args[1]
                if channel_name in self.joined_channels:
                    self.current_channel = channel_name
                    self.text_widget.insert(tk.END, f"Switched to channel {self.current_channel}\r\n")
                    self.display_last_messages(self.current_channel)
                    self.gui.highlight_nickname()
                else:
                    self.text_widget.insert(tk.END, f"Not a member of channel {channel_name}\r\n")

            case "quit":
                await self.send_message('QUIT')
                await asyncio.sleep(2)
                self.master.destroy()
                return False

            case "help":
                self.display_help()

            case None:
                if self.current_channel:
                    await self.send_message(f'PRIVMSG {self.current_channel} :{user_input}')
                    self.text_widget.insert(tk.END, f"{timestamp}<{self.nickname}> {user_input}\r\n")
                    self.gui.highlight_nickname()
                    self.gui.insert_and_scroll()
                    
                    # Save the message to the channel_messages dictionary
                    if self.current_channel not in self.channel_messages:
                        self.channel_messages[self.current_channel] = []
                    self.channel_messages[self.current_channel].append(f"{timestamp}<{self.nickname}> {user_input}\r\n")
                    
                    # Trim the messages list if it exceeds 200 lines
                    if len(self.channel_messages[self.current_channel]) > 200:
                        self.channel_messages[self.current_channel] = self.channel_messages[self.current_channel][-200:]
                else:
                    self.text_widget.insert(tk.END, "No channel selected. Use /join to join a channel.\r\n")

            case _:
                self.text_widget.insert(tk.END, "Invalid command. Type /help for a list of commands.\r\n")

        return True

    async def handle_action(self, args):
        action_message = ' '.join(args[1:])
        formatted_message = f"* {self.nickname} {action_message}"
        await self.send_message(f'PRIVMSG {self.current_channel} :\x01ACTION {action_message}\x01')
        timestamp = datetime.datetime.now().strftime('[%H:%M:%S] ')
        self.text_widget.insert(tk.END, f"{timestamp}{formatted_message}\r\n")
        self.gui.highlight_nickname()
        self.gui.insert_and_scroll()

        # Save the action message to the channel_messages dictionary
        if self.current_channel not in self.channel_messages:
            self.channel_messages[self.current_channel] = []
        self.channel_messages[self.current_channel].append(f"{timestamp}{formatted_message}\r\n")

        # Trim the messages list if it exceeds 200 lines
        if len(self.channel_messages[self.current_channel]) > 200:
            self.channel_messages[self.current_channel] = self.channel_messages[self.current_channel][-200:]

    def display_help(self):
        self.text_widget.insert(tk.END, "/join <channel> joins a channel\r\n")
        self.text_widget.insert(tk.END, "/part <channel> leaves a channel\r\n")
        self.text_widget.insert(tk.END, "/ch shows channels joined\r\n")
        self.text_widget.insert(tk.END, "/sw <channel> switches to a channel\r\n")
        self.text_widget.insert(tk.END, "/quit closes connection and client\r\n")
        self.text_widget.insert(tk.END, "/help redisplays this message\r\n")

    def set_gui(self, gui):
        self.gui = gui

    async def main_loop(self):
        while True:
            try:
                loop = asyncio.get_event_loop()
                user_input = await loop.run_in_executor(None, input, f'{self.current_channel} $ {self.nickname}')
                should_continue = await self.command_parser(user_input)
                if not should_continue:
                    break
            except KeyboardInterrupt:
                await self.send_message('QUIT')
                break

    async def start(self):
        await self.connect()
        if self.nickserv_password:
            await self.send_message(f'PRIVMSG NickServ :IDENTIFY {self.nickserv_password}')

        asyncio.create_task(self.keep_alive())
        asyncio.create_task(self.handle_incoming_message())

        await self.main_loop()

    def display_last_messages(self, channel, num=200):
        messages = self.channel_messages.get(channel, [])
        for message in messages[-num:]:
            self.text_widget.insert(tk.END, message)


class IRCGui:
    def __init__(self, master):
        self.master = master
        self.master.title("RudeChat")
        self.master.geometry("1200x900")
        self.master.configure(bg="black")

        self.frame = tk.Frame(self.master, bg="black")
        self.frame.pack(expand=1, fill='both')

        self.channel_lists = {}
        self.server_users = {}

        # Server selection dropdown menu
        self.server_var = tk.StringVar(self.master)
        self.server_dropdown = ttk.Combobox(self.master, textvariable=self.server_var, width=20) 
        self.server_dropdown.pack(side='top', anchor='w')
        self.server_dropdown['values'] = []
        self.server_dropdown.bind('<<ComboboxSelected>>', self.on_server_change)

        self.clients = {}

        # Use ScrolledText widget for main chat area
        self.text_widget = ScrolledText(self.frame, wrap='word', bg="black", fg="#C0FFEE")
        self.text_widget.pack(side="left", expand=1, fill='both')
        self.text_widget.tag_configure("nickname", foreground="#39ff14")

        # Frame to hold both User and Channel listboxes
        self.list_frame = tk.Frame(self.frame, bg="black")
        self.list_frame.pack(side="right", fill='y')

        # Frame for User List
        self.user_frame = tk.Frame(self.list_frame, bg="black")
        self.user_frame.pack(side='top', fill='both')

        # User list label and Listbox widget with Scrollbar
        self.user_label = tk.Label(self.user_frame, text="Users", bg="black", fg="white")
        self.user_label.pack(side='top', fill='x')
        self.user_listbox = tk.Listbox(self.user_frame, height=25, width=16, bg="black", fg="#39ff14")
        self.user_scrollbar = tk.Scrollbar(self.user_frame, orient="vertical", command=self.user_listbox.yview)
        self.user_listbox.config(yscrollcommand=self.user_scrollbar.set)
        self.user_listbox.pack(side='left', expand=1, fill='both')
        self.user_scrollbar.pack(side='right', fill='y')

        # Frame for Channel List
        self.channel_frame = tk.Frame(self.list_frame, bg="black")
        self.channel_frame.pack(side='top', fill='both')

        # Channel list label and Listbox widget with Scrollbar
        self.channel_label = tk.Label(self.channel_frame, text="Channels", bg="black", fg="white")
        self.channel_label.pack(side='top', fill='x')
        self.channel_listbox = tk.Listbox(self.channel_frame, height=20, width=16, bg="black", fg="white")
        self.channel_scrollbar = tk.Scrollbar(self.channel_frame, orient="vertical", command=self.channel_listbox.yview)
        self.channel_listbox.config(yscrollcommand=self.channel_scrollbar.set)
        self.channel_listbox.pack(side='left', expand=1, fill='both')
        self.channel_scrollbar.pack(side='right', fill='y')
        self.channel_listbox.bind('<ButtonRelease-1>', self.on_channel_click)

        # Server Console using ScrolledText widget
        self.server_frame = tk.Frame(self.master, height=100, bg="black")
        self.server_frame.pack(side='top', fill='x')
        self.server_text_widget = ScrolledText(self.server_frame, wrap='word', height=5, bg="black", fg="#7882ff")
        self.server_text_widget.pack(side="left", expand=1, fill='both')

        self.entry_widget = tk.Entry(self.master)
        self.entry_widget.pack(side='bottom', fill='x')

        # Initialize the current nickname and channel label variable
        self.current_nick_channel = tk.StringVar(value="Nickname | #Channel" + " &>")
        
        # Create a label to display the current nickname and channel
        self.nick_channel_label = tk.Label(self.master, textvariable=self.current_nick_channel, bg="black", fg="white", padx=5, pady=1)
        self.nick_channel_label.pack(side='left', fill='y', before=self.entry_widget)

        # Initialize the AsyncIRCClient and set the GUI reference
        self.irc_client = AsyncIRCClient(self.text_widget, self.server_text_widget, self.entry_widget, self.master, self)

    def add_client(self, server_name, irc_client):
        self.clients[server_name] = irc_client
        current_servers = list(self.server_dropdown['values'])
        current_servers.append(server_name)
        self.server_dropdown['values'] = current_servers
        self.server_var.set(server_name)  # Set the current server
        self.channel_lists[server_name] = irc_client.joined_channels

    def on_server_change(self, event):
        selected_server = self.server_var.get()
        self.irc_client = self.clients.get(selected_server, None)
        if self.irc_client:
            self.irc_client.set_gui(self)
            self.irc_client.update_gui_channel_list()
        # Update the user list in GUI
        selected_channel = self.irc_client.current_channel
        if selected_channel:
            self.irc_client.update_gui_user_list(selected_channel)

    async def init_client_with_config(self, config_file, fallback_server_name):
        irc_client = AsyncIRCClient(self.text_widget, self.server_text_widget, self.entry_widget, self.master, self)
        await irc_client.read_config(config_file)
        await irc_client.connect()

        # Use the server_name if it is set in the configuration, else use fallback_server_name
        server_name = irc_client.server_name if irc_client.server_name else fallback_server_name
        
        self.add_client(server_name, irc_client)
        if irc_client.nickserv_password:
            await irc_client.send_message(f'PRIVMSG NickServ :IDENTIFY {irc_client.nickserv_password}')
        asyncio.create_task(irc_client.keep_alive())
        asyncio.create_task(irc_client.handle_incoming_message())

        async def on_enter_key(event):
            user_input = self.entry_widget.get()
            self.entry_widget.delete(0, tk.END)
            await self.irc_client.command_parser(user_input)
            self.text_widget.see(tk.END)  # Auto-scroll to the bottom

        loop = asyncio.get_event_loop()
        self.entry_widget.bind('<Return>', lambda event: loop.create_task(on_enter_key(event)))

    def on_channel_click(self, event):
        loop = asyncio.get_event_loop()
        # Get index of clicked item
        clicked_index = self.channel_listbox.curselection()
        if clicked_index:
            clicked_channel = self.channel_listbox.get(clicked_index[0])
            loop.create_task(self.switch_channel(clicked_channel))

            # Clear all background color changes in the channel listbox
            for idx in range(self.channel_listbox.size()):
                self.channel_listbox.itemconfig(idx, {'bg': 'black'})

    async def switch_channel(self, channel_name):
        # Clear the text window
        self.text_widget.delete(1.0, tk.END)
        
        if channel_name in self.irc_client.joined_channels:
            self.irc_client.current_channel = channel_name
            self.update_nick_channel_label()
            self.text_widget.insert(tk.END, f"Switched to channel {self.irc_client.current_channel}\r\n")
            
            # Display the last messages for the current channel
            self.irc_client.display_last_messages(self.irc_client.current_channel)
            
            self.irc_client.update_gui_user_list(channel_name)
            self.insert_and_scroll()
        else:
            self.text_widget.insert(tk.END, f"Not a member of channel {channel_name}\r\n")

    def insert_and_scroll(self):
        self.text_widget.see(tk.END)
        self.server_text_widget.see(tk.END)

    def update_nick_channel_label(self):
        """Update the label with the current nickname and channel."""
        nickname = self.irc_client.nickname if self.irc_client.nickname else "Nickname"
        channel = self.irc_client.current_channel if self.irc_client.current_channel else "#Channel"
        self.current_nick_channel.set(f"{nickname} | {channel}" + " $>")

    def highlight_nickname(self):
        """Highlight the user's nickname in the text_widget."""
        nickname = self.irc_client.nickname
        if not nickname:
            return

        # Start at the beginning of the text_widget
        start_idx = "1.0"
        while True:
            # Find the position of the next instance of the nickname
            start_idx = self.text_widget.search(nickname, start_idx, stopindex=tk.END)
            if not start_idx:
                break

            # Calculate the end index based on the length of the nickname
            end_idx = self.text_widget.index(f"{start_idx}+{len(nickname)}c")

            # Apply the tag to the found nickname
            self.text_widget.tag_add("nickname", start_idx, end_idx)

            # Update the start index to search from the position after the current found nickname
            start_idx = end_idx

def main():
    root = tk.Tk()
    app = IRCGui(root)

    loop = asyncio.get_event_loop()

    async def initialize_clients():
        # List all files in the current directory
        files = os.listdir()

        # Filter out files that match the pattern "confX.rude" where X is a number
        config_files = [f for f in files if f.startswith("conf") and f.endswith(".rude")]

        # Sort the config files to maintain order
        config_files.sort()

        # Initialize clients for each config file
        for i, config_file in enumerate(config_files):
            fallback_server_name = f'Server_{i+1}'
            
            try:
                await app.init_client_with_config(config_file, fallback_server_name)
            except OSError as e:
                if e.errno == 121:  # Handle the semaphore timeout error
                    print("Error: Connection timeout. Retrying...")
                else:
                    # If it's another error, raise or handle differently.
                    raise

        # Automatically select the first server if there are any
        if app.server_dropdown['values']:
            first_server = app.server_dropdown['values'][0]
            app.server_var.set(first_server)
            app.on_server_change(None)

    loop.create_task(initialize_clients())

    def tk_update():
        try:
            loop.stop()
            loop.run_forever()
        finally:
            loop.stop()
            root.after(100, tk_update)

    root.after(100, tk_update)
    root.mainloop()

if __name__ == '__main__':
    main()
