
# An Automated Payload Manager
**Author:** [Raya Alotaibi](https://github.com/rayaotb)

### Description

This Python program is designed to assist pentesters in conducting internal and offline penetration tests without the need for an internet connection. It is tailored to ethical hackers that need to simplify file upload tests and establish reverse shell connections in local and offline environments.

### Prerequisites
- Python
- Tkinter (GUI)

### Usage

**GUI features**:
1. Listener Options: Dropdown for listener.
2. Payload Options: Dropdown for reverse shell payload.
3. Encoding Options: Dropdown for encoding method (Optional).
4. Attacker's IP Address: Textfield for the tester's IP address, for the target system to connect back to for the reverse shell.
5. Attacker's Port: Textfield for the port to listen in on.
6. Filename: Textfield to enter the filename to save the generated payload (Optional). When blank, filename will default to "output.txt."

**Generating payload & clipboard**:
- Click the "Generate Payload" button. The program will generate the reverse shell payload and the corresponding listener command based on the user's choices.
- Alternatively, the user can copy the generated payload and listener command from the GUI.


### Disclaimer

The program is designed for educational and legitimate testing purposes only. Just use this tool responsibly and ethically.

Anywho, happy pentesting!
