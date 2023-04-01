# hegaa.jarad

import re
import tkinter as tk
import random
import ipaddress
import ipwhois
import pycountry
from collections import OrderedDict

xlat = [0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39, 0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37]

def clear_input():
    input_box.delete("1.0", "end")

def clear_output():
    output_box.delete("1.0", "end")

def is_cisco_level7_hash(s):
    pattern = re.compile('^([0-9A-Fa-f]{2})([0-9A-Fa-f]+)$')
    match = pattern.match(s)
    if match:
        start = int(match.group(1), 16)
        length = len(match.group(2))
        return True
    else:
        return False

def remove_special_chars(s):
    # Remove non-printable ASCII characters
    return re.sub(r'[^\x20-\x7E]', '', s)

def decrypt_type7(enPassw):
    ep = enPassw
    dp = ''
    regex = re.compile('(^[0-9A-Fa-f]{2})([0-9A-Fa-f]+)')
    result = regex.search(ep)
    s, e = int(result.group(1)), result.group(2)
    for pos in range(0, len(e), 2):
        magic = int(e[pos] + e[pos + 1], 16)
        if s <= 50:
            # xlat length is 51
            newchar = '%c' % (magic ^ xlat[s])
            s += 1
        if s == 51: s = 0
        dp += newchar
    return dp

def decrypt_callback():
    input_text = input_box.get("1.0", "end-1c")
    decrypted_text = ""
    for line in input_text.splitlines():

        try:
            if ":" in line:
                keWord1 = str(line).split(":")[0]
                HashLine = str(line).split(":")[1]
                decrypted_line = decrypt_type7(HashLine)
                while True:
                    testo = is_cisco_level7_hash(decrypted_line)
                    if testo == True:
                        decrypted_line = decrypt_type7(decrypted_line)
                    else:
                        decrypted_line = remove_special_chars(decrypted_line)
                        decrypted_line = f"{keWord1}:{str(decrypted_line)}"
                        decrypted_text += decrypted_line + "\n"
                        break
            else:
                HashLine = str(line)
                decrypted_line = decrypt_type7(HashLine)
                while True:
                    testo = is_cisco_level7_hash(decrypted_line)
                    if testo == True:
                        decrypted_line = decrypt_type7(decrypted_line)
                    else:
                        decrypted_line = remove_special_chars(decrypted_line)
                        decrypted_line = f"{str(decrypted_line)}"
                        decrypted_text += decrypted_line + "\n"
                        break

        except:
            pass
    output_box.delete("1.0", "end")
    output_box.insert("1.0", decrypted_text)

def remove_duplicates():
    input_text = input_box.get("1.0", "end-1c")
    unique_lines = list(OrderedDict.fromkeys(input_text.splitlines()))
    output_text = "\n".join(unique_lines)
    output_box.delete("1.0", "end")
    output_box.insert("1.0", output_text)

def extract_ips():
    input_text = input_box.get("1.0", "end-1c")
    ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', input_text)
    Fline = ""
    for line in ips:
        if ipaddress.IPv4Address(line):
            if str(line).split(".")[0] == "0" or str(line).split(".")[0] == "255":
                pass
            else:
                Fline += line + "\n"
        else:
            pass
    output_text = Fline
    output_box.delete("1.0", "end")
    output_box.insert("1.0", output_text)

def extract_ips_24():
    input_text = input_box.get("1.0", tk.END)
    lines = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', input_text)
    cidrs = set()

    for line in lines:
        try:
            if str(line).split(".")[0] == "0" or str(line).split(".")[0] == "255":
                pass
            else:
                ip = ipaddress.ip_address(line.strip())
                cidr = f"{ip}/24"
                network = ipaddress.ip_network(f"{cidr}", strict=False)
                cidrs.add(network)
        except ValueError:
            pass

    cidr_list = list(cidrs)
    cidr_list.sort()
    output_box.delete("1.0", tk.END)

    for cidr in cidr_list:
        output_box.insert(tk.END, f"{cidr}\n")

def extract_ips_16():
    input_text = input_box.get("1.0", tk.END)

    lines = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', input_text)

    cidrs = set()

    for line in lines:
        try:
            if str(line).split(".")[0] == "0" or str(line).split(".")[0] == "255":
                pass
            else:
                ip = ipaddress.ip_address(line.strip())
                cidr = f"{ip}/16"
                network = ipaddress.ip_network(f"{cidr}", strict=False)
                cidrs.add(network)
        except ValueError:
            pass

    cidr_list = list(cidrs)

    cidr_list.sort()

    output_box.delete("1.0", tk.END)

    for cidr in cidr_list:
        output_box.insert(tk.END, f"{cidr}\n")

def generate_ips():
    input_text = input_box.get("1.0", tk.END)

    lines = input_text.splitlines()

    ips = []

    for line in lines:
        try:
            network = ipaddress.IPv4Network(line.strip())
            for ip in network.hosts():
                ips.append(str(ip))
        except ValueError:
            pass

    ip_list = ips
    # Clear the contents of the output_box text box
    output_box.delete("1.0", tk.END)

    # Insert the sorted list of IPs into the output_box text box
    for ip in ip_list:
        output_box.insert(tk.END, f"{ip}\n")

def get_ip_info():
    input_text = input_box.get("1.0", "end-1c")
    ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', input_text)
    ipsL = []
    for line in ips:
        if ipaddress.IPv4Address(line):
            if str(line).split(".")[0] == "0" or str(line).split(".")[0] == "255":
                pass
            else:
                ipsL.append(line)
        else:
            pass

    output = ''
    for ip in ipsL:
        if ip.strip():
            try:
                ip_info = ipwhois.IPWhois(ip)
                results = ip_info.lookup_rdap()
                country_code = results["asn_country_code"]
                country_name = pycountry.countries.get(alpha_2=country_code).name
                output += f'{ip} - {country_name} - AS{results["asn"]}\n'
            except ipwhois.exceptions.IPDefinedError:
                pass
            except:
                pass
    output_box.delete('1.0', tk.END)
    output_box.insert(tk.END, output)

def add_text():
    input_text = input_box.get("1.0", "end-1c")
    add_text = add_box.get()
    output_text = ""
    for line in input_text.splitlines():
        output_text += line + add_text + "\n"
    output_box.delete("1.0", "end")
    output_box.insert("1.0", output_text)

def add_before():
    input_text = input_box.get("1.0", "end-1c")
    add_text = add_box.get()
    output_text = ""
    for line in input_text.splitlines():
        output_text += add_text + line + "\n"
    output_box.delete("1.0", "end")
    output_box.insert("1.0", output_text)

def find_lines():
    keyword = add_box.get()
    lines = input_box.get("1.0", "end-1c").split("\n")
    results = [line for line in lines if keyword in line]
    output_box.delete("1.0", "end")
    output_box.insert("1.0", "\n".join(results))

def shuffle_text():
    # Get all text lines from input_box
    text_lines = input_box.get('1.0', 'end').splitlines()
    # Shuffle the text lines randomly
    random.shuffle(text_lines)
    # Clear the output_box
    output_box.delete('1.0', 'end')
    # Insert the shuffled lines into the output_box
    output_box.insert('1.0', '\n'.join(text_lines))

def convert_to_comma_lists():
    # Get the comma separator from the add_box Entry
    comma = add_box.get()
    # Get the number of elements per list from the EML Entry
    num_elems = int(EML.get())
    # Get all text lines from input_box
    text_lines = input_box.get('1.0', 'end').splitlines()
    # Convert the text lines to comma-delimited lists
    comma_lists = []
    for i in range(0, len(text_lines), num_elems):
        comma_lists.append(comma.join(text_lines[i:i+num_elems]))
    # Clear the output_box
    output_box.delete('1.0', 'end')
    # Insert the comma-delimited lists into the output_box
    output_box.insert('1.0', '\n'.join(comma_lists))

def extract_phone_numbers():
    # Get all text from input_box
    text = input_box.get('1.0', 'end')
    # Extract phone numbers using regular expressions
    phone_numbers = re.findall(r"\b\d{8,16}\b", text)
    # Clear the output_box
    output_box.delete('1.0', 'end')
    # Insert the phone numbers into the output_box
    output_box.insert('1.0', '\n'.join(phone_numbers))

def generate_numbers():
    start = int(Gen_Start.get())
    end = int(Gen_End.get())
    numbers = list(range(start, end+1))
    output_box.delete("1.0", tk.END)  # clear previous output
    output_box.insert(tk.END, "\n".join(map(str, numbers)))

# create the GUI window
root = tk.Tk()

# set the window title
root.title("Hegaa.jarad Tools ")
root.resizable(False, False)

# create the input text box
input_box = tk.Text(root, height=20, width=30)
input_box.grid(row=1, column=1,  rowspan=9,sticky="nsew")

# create the output text box
output_box = tk.Text(root, height=20, width=30)
output_box.grid(row=1, column=6,  rowspan=9, sticky="nsew")

# Clear Input N output boxs
clear_button_input = tk.Button(root, text="C", width=1, command=clear_input)
clear_button_input.grid(row=1, column=2, pady=5)

clear_button_input = tk.Button(root, text="C", command=clear_output)
clear_button_input.grid(row=1, column=5, pady=5)

root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_rowconfigure(0, weight=1)


# create the Decrypt button
decrypt_button = tk.Button(root, text="Dec7", command=decrypt_callback)
decrypt_button.grid(row=1, column=3, pady=1)


# remove_duplicates
dup_button = tk.Button(root, text="Dup", command=remove_duplicates)
dup_button.grid(row=2, column=3, pady=5)


# extract_ips
ips_button = tk.Button(root, text="IPS", command=extract_ips)
ips_button.grid(row=3, column=4, pady=5)

# extract_ips_24
ips_button_24 = tk.Button(root, text="IP24", command=extract_ips_24)
ips_button_24.grid(row=3, column=2, pady=5)

# extract_ips_16
ips_button_24 = tk.Button(root, text="IP16", command=extract_ips_16)
ips_button_24.grid(row=3, column=3, pady=5)

# generate_ips
ips_button_24 = tk.Button(root, text="GIP", command=generate_ips)
ips_button_24.grid(row=3, column=5, pady=5)

# get_ip_info
get_ip_info = tk.Button(root, text="Info", command=get_ip_info)
get_ip_info.grid(row=4, column=2, pady=5)

# find_lines
find_button = tk.Button(root, text="Find", command=find_lines)
find_button.grid(row=4, column=3, pady=5)

# shuffle_text
random_button = tk.Button(root, text='Random', command=shuffle_text)
random_button.grid(row=4, column=4, pady=5)


# Adding Text Before N after
add_box = tk.Entry(root, width=8)
add_box.insert(0, ":5060")
add_box.grid(row=5, column=3, pady=1)

add_button_before = tk.Button(root, text="<", command=add_before)
add_button_before.grid(row=5, column=2, pady=1)

add_button_after = tk.Button(root, text=">", command=add_text)
add_button_after.grid(row=5, column=4, pady=1)

# convert_to_comma_lists
EML = tk.Entry(root, width=8)
EML.grid(row=6, column=3, pady=1)

ML_button = tk.Button(root, text='ML', command=convert_to_comma_lists)
ML_button.grid(row=6, column=2, pady=1)

# generate_numbers
Gen_Start = tk.Entry(root, width=5)
Gen_Start.insert(0, "1")
Gen_Start.grid(row=7, column=2, pady=1)

Gen_End = tk.Entry(root, width=5)
Gen_End.insert(0, "100")
Gen_End.grid(row=7, column=3, pady=1)

Gen_button = tk.Button(root, text='GEN', command=generate_numbers)
Gen_button.grid(row=7, column=4, pady=1)

# extract_phone_numbers
phone_button = tk.Button(root, text='Phone', command=extract_phone_numbers)
phone_button.grid(row=8, column=3, pady=5)


# start the GUI loop
root.mainloop()
