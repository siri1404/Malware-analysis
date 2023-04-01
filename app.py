from flask import Flask, render_template, request, redirect, url_for
import os
import pefile
import hashlib
import magic
import datetime
import subprocess
import math
from collections import Counter
import pathlib
from scapy.all import *
from scapy.all import *
from scapy.layers.inet import TCP, UDP
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
import dpkt
import socket

app = Flask(__name__)

# function to parse a pcap file and extract HTTP request information
def parse_pcap_file(filename):
    # open the pcap file
    with open(filename, 'rb') as f:
        # create a pcap reader object
        pcap_reader = dpkt.pcap.Reader(f)
        
        # initialize a dictionary to hold the extracted information
        events = []
        
        # loop through each packet in the pcap file
        for timestamp, buf in pcap_reader:
            try:
                # parse the packet using dpkt
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                
                # check if the packet is an HTTP request
                if tcp.dport == 80:
                    # extract the desired information from the packet
                    http = dpkt.http.Request(tcp.data)
                    pid = ""
                    process = ""
                    method = http.method
                    http_code = ""
                    ip_addr = socket.inet_ntoa(ip.src)
                    url = http.uri
                    cn = ""
                    event_type = "HTTP Request"
                    size = len(tcp.data)
                    reputation = ""
                    
                    # add the extracted information to the dictionary
                    events.append({
                        "PID": pid,
                        "Process": process,
                        "Method": method,
                        "HTTP Code": http_code,
                        "IP": ip_addr,
                        "URL": url,
                        "CN": cn,
                        "Type": event_type,
                        "Size": size,
                        "Reputation": reputation
                    })
            except:
                pass
                
        # print the extracted information
        for event in events:
            print(event)


def capture_traffic(filename):
    # Start process
    proc = subprocess.Popen(filename)

    # Start capturing packets
    packets = sniff(filter='tcp port 80', timeout=10)

    # Stop process
    proc.kill()

    # Save captured packets to PCAP file
    wrpcap('traffic.pcap', packets)

# function to count the number of HTTP(S) requests, TCP/UDP connections, and DNS requests
def count_requests(filename):
    # read the pcap file
    packets = rdpcap(filename)
    
    # initialize counters
    http_requests = 0
    tcp_connections = 0
    udp_connections = 0
    dns_requests = 0
    
    # loop through each packet
    for packet in packets:
        # check if the packet is a TCP or UDP packet
        if packet.haslayer(TCP):
            tcp_connections += 1
        elif packet.haslayer(UDP):
            udp_connections += 1
        # check if the packet is an HTTP request
        elif packet.haslayer(HTTP):
            http_requests += 1
        # check if the packet is a DNS request
        elif packet.haslayer(DNS):
            dns_requests += 1
    
    # return the results
    return (http_requests, tcp_connections, udp_connections, dns_requests)

def extract_tcp_info(pcap_file):
    tcp_connections = {}
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                # check if packet is TCP
                if isinstance(tcp, dpkt.tcp.TCP):
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    if (src_ip, src_port, dst_ip, dst_port) not in tcp_connections:
                        # new TCP connection
                        tcp_connections[(src_ip, src_port, dst_ip, dst_port)] = {
                            'pid': -1,
                            'process': '',
                            'ip': dst_ip,
                            'domain': socket.getfqdn(dst_ip),
                            'asn': '',
                            'cn': '',
                            'reputation': ''
                        }
            except Exception as e:
                pass # ignore any packets that cannot be parsed
    
    return tcp_connections


# Set upload folder
UPLOAD_FOLDER = os.path.join(os.getcwd(), './')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Home page
@app.route('/')
def home():
    return render_template('home.html')

# Upload PE file
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file:
        # Save the file with its original name
        filename = file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('success', filename=filename))
    else:
        return "File not uploaded"

# Success page
@app.route('/success/<filename>')
def success(filename):
    
    # File name
    filename = os.path.basename(filename)
    pe = pefile.PE(filename)

    # Operating system
    if pe.FILE_HEADER.Machine == 0x14c: # Intel 386
        if pe.OPTIONAL_HEADER.Magic == 0x10b: # PE32
            operating_system = "Windows 95/98/ME"
        elif pe.OPTIONAL_HEADER.Magic == 0x20b: # PE32+
            operating_system = "Windows NT/2000/XP/Vista/7/8/10"
    elif pe.FILE_HEADER.Machine == 0x8664: # AMD64
        if pe.OPTIONAL_HEADER.Magic == 0x10b: # PE32
            operating_system = "Windows NT/2000/XP/Vista/7/8/10"
        elif pe.OPTIONAL_HEADER.Magic == 0x20b: # PE32+
            operating_system = "Windows 7/8/10"

    # MIME type
    mime = "application/octet-stream"

    # File info
    size = pe.FILE_HEADER.SizeOfOptionalHeader
    timestamp = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S')

    # Hashes
    with open(filename, 'rb') as f:
        content = f.read()
        md5 = hashlib.md5(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()
    
    with open(filename, "rb") as f:
        file_data = f.read()

# Get the TRiD information
    magic_cl = magic.Magic(mime=True)
    mime_type = magic_cl.from_buffer(file_data)

    magic_cl = magic.Magic()
    trid_info = magic_cl.from_buffer(file_data)

    File_type = "PE"
    Object_file_type = pe.OPTIONAL_HEADER.Subsystem
    File_OS = "Win32"
    File_flags = hex(pe.FILE_HEADER.Characteristics)
    File_flags_mask = hex(pe.FILE_HEADER.Characteristics)
    Subsystem = pe.OPTIONAL_HEADER.Subsystem
    Subsystem_version = pe.OPTIONAL_HEADER.MajorSubsystemVersion, ".", pe.OPTIONAL_HEADER.MinorSubsystemVersion
    Image_version = pe.OPTIONAL_HEADER.MajorImageVersion, ".", pe.OPTIONAL_HEADER.MinorImageVersion
    OS_version = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion, ".", pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    Entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    Uninitialized_data_size = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    Initialized_data_size = pe.OPTIONAL_HEADER.SizeOfInitializedData
    Code_size = pe.OPTIONAL_HEADER.SizeOfCode
    Linker_version =  pe.OPTIONAL_HEADER.MajorLinkerVersion, ".", pe.OPTIONAL_HEADER.MinorLinkerVersion
    PE_type =  "PE32" if pe.FILE_HEADER.Machine == 0x014c else "PE32+" if pe.FILE_HEADER.Machine == 0x8664 else "Unknown"
    Time_stamp = pe.FILE_HEADER.TimeDateStamp
    Machine_type = "x86" if pe.FILE_HEADER.Machine == 0x014c else "x64" if pe.FILE_HEADER.Machine == 0x8664 else "Unknown"


    architecture = hex(pe.FILE_HEADER.Machine)

# Get the subsystem information
    subsystem = pe.OPTIONAL_HEADER.Subsystem

# Get the compilation date information
    timestamp = pe.FILE_HEADER.TimeDateStamp
    date = datetime.fromtimestamp(timestamp)
    compilation_date = date.strftime("%Y-%m-%d %H:%M:%S")
    
    # Print the DOS header values

# Execute the malicious PE file
    subprocess.run([filename])

# Generate the PAC file
    subprocess.run(["python", "generate_pac_file.py"])


    dos_header = pe.DOS_HEADER
    Magic_number = hex(dos_header.e_magic)
    Bytes_on_last_page_of_file = dos_header.e_cblp
    Pages_in_file = dos_header.e_cp
    Relocations  = dos_header.e_crlc
    Size_of_header  = dos_header.e_cparhdr
    Min_extra_paragraphs = dos_header.e_minalloc
    Max_extra_paragraphs  = dos_header.e_maxalloc
    Initial_SS_value = hex(dos_header.e_ss)
    Initial_SP_value = hex(dos_header.e_sp)
    Checksum = dos_header.e_csum
    Initial_IP_value = hex(dos_header.e_ip)
    Initial_CS_value = hex(dos_header.e_cs)
    printOverlay_number = dos_header.e_ovno
    printOEM_identifier = dos_header.e_oemid
    OEM_information = dos_header.e_oeminfo
    Address_of_NE_header  = hex(dos_header.e_lfanew)

    signature = "0x{:X}".format(pe.DOS_HEADER.e_magic)
    machine = "0x{:X}".format(pe.FILE_HEADER.Machine)
    num_sections = "{}".format(pe.FILE_HEADER.NumberOfSections)
    time_date_stamp = "0x{:X}".format(pe.FILE_HEADER.TimeDateStamp)
    pointer_to_symbol_table = "0x{:X}".format(pe.FILE_HEADER.PointerToSymbolTable)
    num_symbols = "{}".format(pe.FILE_HEADER.NumberOfSymbols)
    size_of_optional_header = "{}".format(pe.FILE_HEADER.SizeOfOptionalHeader)
    characteristics = "0x{:X}".format(pe.FILE_HEADER.Characteristics)
    

    table_data = []
    for section in pe.sections:
        section_data = section.get_data()
        entropy = sum(-p * math.log2(p) for p in Counter(section_data).values() if p != 0)
        table_data.append({
            'name': section.Name.decode().rstrip('\x00'),
            'virtual_address': section.VirtualAddress,
            'virtual_size': section.Misc_VirtualSize,
            'raw_size': section.SizeOfRawData,
            'characteristics': hex(section.Characteristics),
            'entropy': entropy,
        })
    
    imports = [entry.dll.decode('utf-8') for entry in pe.DIRECTORY_ENTRY_IMPORT]

    # Define lists of known process monitoring and malicious behavior imports
    monitoring_imports = ['CreateProcess', 'CreateRemoteThread', 'CreateThread', 'OpenProcess', 'OpenThread', 'Process32First', 'Process32Next', 'ReadProcessMemory', 'WriteProcessMemory']
    malicious_imports = ['DeleteFile', 'MoveFile', 'CopyFile', 'InternetOpen', 'InternetConnect', 'HttpOpenRequest', 'GetAsyncKeyState', 'GetForegroundWindow', 'GetWindowText', 'ShowWindow']

    # Count the total number of imports, monitored imports, and malicious imports
    total_imports = len(imports)
    monitored_imports = len(set(imports).intersection(monitoring_imports))
    malicious_imports = len(set(imports).intersection(malicious_imports))
    
    exe_count = 0
    susp_count = 0
    text_count = 0

    file = "./uploads"
    # Loop through the files in the directory
    for file in pathlib.Path(file).iterdir():
        file_ext = file.suffix.lower()
        if file_ext == ".exe":
            exe_count += 1
        elif file_ext in [".bat", ".cmd", ".ps1"]:
            # add any other suspicious extensions to the list
            susp_count += 1
        elif file_ext in [".txt", ".csv", ".xml", ".html"]:
            # add any other text file extensions to the list
            text_count += 1

    # get the PE file path from the form
    pe_path = filename
    # capture network traffic during the execution of the PE file
    capture_traffic(pe_path)

    # count the number of HTTP(S) requests, TCP/UDP connections, and DNS requests
    http_requests, tcp_connections, udp_connections, dns_requests = count_requests("traffic.pcap")

    # parse the pcap file and extract HTTP request information
    events = parse_pcap_file("traffic.pcap")

    tcp_connection = extract_tcp_info("traffic.pcap")

    # Get the DNS requests
    dns_request = []
    with open("traffic.pcap", "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if isinstance(ip.data, dpkt.udp.UDP) and ip.data.dport == 53:
                dns = dpkt.dns.DNS(ip.data.data)
                for query in dns.qd:
                    dns_request.append({"domain": query.name, "ip": None})
                for rr in dns.an:
                    if rr.type == dpkt.dns.DNS_A:
                        dns_request[-1]["ip"] = dpkt.inet_ntoa(rr.rdata)
    # Get the process information
    pid_to_name = {}
    with open("traffic.pcap", "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP):
                pid = ip.data.dport
                payload = ip.data.data
                if b"pid=" in payload:
                    pid = int(payload.split(b"pid=")[1].split(b"&")[0])
                    process_name = payload.split(b"name=")[1].split(b"&")[0].decode("utf-8")
                    pid_to_name[pid] = process_name
    process_info = [{"pid": k, "process": v} for k, v in pid_to_name.items()]

    # render the results template
    return render_template('success.html', filename=filename, os=operating_system, mime=mime, size=size, timestamp=timestamp, md5=md5, sha1=sha1, sha256=sha256,mime_type=mime_type,trid_info=trid_info 
    , File_type=File_type,Object_file_type=Object_file_type, File_OS=File_OS, File_flags=File_flags, File_flags_mask=File_flags_mask, Subsystem=Subsystem, Subsystem_version=Subsystem_version,Image_version=Image_version, OS_version=OS_version, Entry_point=Entry_point, Uninitialized_data_size=Uninitialized_data_size,Pages_in_file=Pages_in_file,
    Initialized_data_size=Initialized_data_size, Code_size=Code_size, Linker_version=Linker_version, PE_type=PE_type, Time_stamp=Time_stamp, Machine_type=Machine_type, architecture=architecture, subsystem=subsystem, compilation_date=compilation_date,Min_extra_paragraphs=Min_extra_paragraphs, Size_of_header=Size_of_header,Relocations=Relocations, Bytes_on_last_page_of_file=Bytes_on_last_page_of_file
    ,Magic_number=Magic_number,Address_of_NE_header=Address_of_NE_header, OEM_information=OEM_information, printOEM_identifier=printOEM_identifier, printOverlay_number=printOverlay_number, Initial_CS_value=Initial_CS_value, Initial_IP_value=Initial_IP_value, Checksum=Checksum,Initial_SP_value=Initial_SP_value,Initial_SS_value=Initial_SS_value, Max_extra_paragraphs=Max_extra_paragraphs, signature=signature, machine=machine, num_sections=num_sections,
    time_date_stamp=time_date_stamp, pointer_to_symbol_table=pointer_to_symbol_table,num_symbols=num_symbols, size_of_optional_header=size_of_optional_header, characteristics=characteristics, table_data=table_data,total_imports=total_imports, monitored_imports=monitored_imports, malicious_imports=malicious_imports,exe_count=exe_count, susp_count=susp_count, text_count=text_count,http_requests=http_requests, tcp_connections=tcp_connections, udp_connections=udp_connections, dns_requests=dns_requests,events=events ,
     tcp_connection=tcp_connection,dns_request=dns_request, process_info=process_info )


if __name__ == '__main__':
    app.run(debug=True)