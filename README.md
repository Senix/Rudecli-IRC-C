# Rudecli-IRC-C
Rudecli is a Rudimentary IRC Client hence the name, it is designed to be small, portable, and fast.

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

IRCClient class: It represents the IRC client and manages the connection, message handling, channel management, and user interactions.

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

IRCClientGUI class: It represents the graphical user interface for the IRC client using Tkinter.

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
