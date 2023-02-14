#!/usr/share/python3

import requests
import optparse
from colorama import Fore, Back, Style
import urllib.parse as urlparse
import re
import pyfiglet
from pythonping import ping
import socket

# This is a website enumeration and exploitation Program
# Author : Aditya Patil
# Python Version Tested on : 3.10.7
# Usage : Python3 [arguements]
#         Arguements:
#                    -h, --help : To show help
#                    -u, --url : To specify the Target URL
#                    -w, --wordlist : To specify the wordlist containing subdomain or directories as per requirements
#                    -m, --mode : To specify the mode of enumeration [sub (subdomain), dir (directory), spy (spider), all]
#                    -v, --verbose : Verbose mode True/true. False/false if not specified
#                    -i, --ipaddress : To get the IP Address of the server. (True/true), False/false if not specified
#                    -r , --header : To fetch the header information that may contain valuable information about the specified website

def get_arguements():

    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", help="To specify the target URL. Provide the URL like target.com", dest="target_url")
    parser.add_option("-w", "--wordlist", help="To specify wordlist containing subdomains or directories as per requirements", dest="wordlist_path")
    parser.add_option("-m", "--mode", help="To specify mode of enumeration (sub, dir, spy)", dest="mode")
    parser.add_option("-v", "--verbose", help="Verbose mode on (to print more information) (true or false)", dest="verbose")
    parser.add_option("-i", "--ipaddress", help="Ping the server for IP Address (true/false)", dest="ip_mode")
    parser.add_option("-r", "--header", help="To fetch the header information that may contain valuable information about the specified website (std-req, com-nstd-req, std-resp, com-nstd-resp, all (prefered)", dest="header_mode")
    parser.add_option("-l", "--login-detection", help="To enumerate for login pages for found websites", dest="lgndtc_mode")
    parser.add_option("-p", "--port-scan", help="To start a port scan againt the target server", dest="port_scan_option")

    (options, arguements) = parser.parse_args()
    user_mode = options.mode
    port_scan_option = options.port_scan_option

    if not options.target_url:
        parser.error("[-] Please provide the Target URL!")

    if not port_scan_option:
        if not options.mode:
            parser.error("[-] Please provide the mode of enumeration!")

    if user_mode == "sub" or user_mode == "subdomain" or user_mode == "dir" or user_mode == "directory" or user_mode == "all":
        if not options.wordlist_path:
            parser.error("[-] Please provide the wordlist path!")

    return options

def normal_get_request(url):

    response = requests.get("http://" + url)
    return response

def get_ip(url):

    ping_response = ping(url, count=1)
    ping_response = re.findall('(?:Reply from )(\d*.\d*.\d*.\d*)', str(ping_response))
    for ip in ping_response:
        return ip

def port_scan(ip, port):       # Work on this functions

    try:
        connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection_socket.connect((ip, port))
        status = True
    except:
        status = False
    return status

def field_printer(array_of_fields, dictionary_of_header_fields):
    for field in array_of_fields:
        if field in dictionary_of_header_fields:
            value = dictionary_of_header_fields[field]
            print(Style.RESET_ALL + Fore.BLUE + "[+] " + field + " : " + Fore.WHITE + value + Style.RESET_ALL)

def http_header_data(url):
    get_request = normal_get_request(url)
    header = get_request.headers
    standard_request_fields = ['A-IM', 'Accept', 'Accept-Charset', 'Accept-Datetime', 'Accept-Encoding', 'Accept-Language', 'Access-Control-Request-Method', 'Access-Control-Request-Headers', 'Authorization', 'Cache-Control', 'Connection', 'Content-Encoding', 'Content-Length', 'Content-MD5', 'Content-Type', 'Cookie', 'Date', 'Expect', 'Forwarded', 'From', 'Host', 'HTTP2-Settings', 'If-Match', 'If-Modified-Since', 'If-None-Match', 'If-Range', 'If-Unmodified-Since', 'Max-Forwards', 'Origin', 'Pragma', 'Prefer', 'Proxy-Authorization', 'Range', 'Referer', 'TE', 'Trailer', 'Transfer-Encoding', 'User-Agent', 'Upgrade', 'Via', 'Warning']
    common_non_standard_request_fields = ['Upgrade-Insecure-Requests', 'X-Requested-With', 'DNT', 'X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto', 'Front-End-Https', 'X-Http-Method-Override', 'X-ATT-DeviceId', 'X-Wap-Profile', 'Proxy-Connection', 'X-UIDH', 'X-Csrf-Token', 'X-Request-ID', 'X-Correlation-ID', 'Correlation-ID', 'Save-Data']
    standard_response_fields = ['Accept-CH', 'Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials', 'Access-Control-Expose-Headers', 'Access-Control-Max-Age', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Headers', 'Accept-Patch', 'Accept-Ranges', 'Age', 'Allow', 'Alt-Svc', 'Cache-Control', 'Connection', 'Content-Disposition', 'Content-Encoding', 'Content-Language', 'Content-Length', 'Content-Location', 'Content-MD5', 'Content-Range', 'Content-Type', 'Date', 'Delta-Base', 'ETag', 'Expires', 'IM', 'Last-Modified', 'Link', 'Location', 'P3P', 'Pragma', 'Preference-Applied', 'Proxy-Authenticate', 'Public-Key-Pins', 'Retry-After', 'Server', 'Set-Cookie', 'Strict-Transport-Security', 'Trailer', 'Transfer-Encoding', 'Tk', 'Upgrade', 'Vary', 'Via', 'Warning', 'WWW-Authenticate', 'X-Frame-Options']
    common_non_standard_response_field = ['Content-Security-Policy', 'X-Content-Security-Policy', 'X-WebKit-CSP', 'Expect-CT', 'NEL', 'Permissions-Policy', 'Refresh', 'Report-To', 'Status', 'Timing-Allow-Origin', 'X-Content-Duration', 'X-Content-Type-Options', 'X-Powered-By', 'X-Redirect-By', 'X-Request-ID', 'X-Correlation-ID', 'X-UA-Compatible', 'X-XSS-Protection']

    check = 0
    valid_header_mode_options = ['std-req', 'com-nstd-req', 'std-resp', 'com-nstd-resp', 'all']
    for valid_option in valid_header_mode_options:
        if valid_option != header_mode:
            check += 1
    if check == 5:
        print("[-] Valid arguement to header mode option was not provided, skipping HTTP-Header scan .... \n")

    if header_mode == "std-req":
        try:
            field_printer(standard_request_fields, header)
        except Exception:
            print("[-] Failed to fetch Standard Request Fields data")
    if header_mode == "com-nstd-req":
        try:
            field_printer(common_non_standard_request_fields, header)
        except Exception:
            print("[-] Failed to fetch Common Non-Standard Request Fields data")
    if header_mode == "std-resp":
        try:
            field_printer(standard_response_fields, header)
        except Exception:
            print("[-] Failed to fetch Standard Response Fields data")
    if header_mode == "com-nstd-resp":
        try:
            field_printer(common_non_standard_response_field, header)
        except Exception:
            print("[-] Failed to fetch Common Non-Standard Response Fields data")

    if header_mode == "all":
        try:
            print(Fore.GREEN + "\n[+] Standard Request Fields data : \n")
            field_printer(standard_request_fields, header)
        except Exception:
            print("[-] Failed to fetch Standard Request Fields data")
        try:
            print(Fore.GREEN + "\n[+] Common Non-Standard Request Fields data : \n")
            field_printer(common_non_standard_request_fields, header)
        except Exception:
            print("[-] Failed to fetch Common Non-Standard Request Fields data")
        try:
            print(Fore.GREEN + "\n[+] Standard Response Fields data : \n")
            field_printer(standard_response_fields, header)
        except Exception:
            print("[-] Failed to fetch Standard Response Fields data")
        try:
            print(Fore.GREEN + "\n[+] Common Non-Standard Response Fields data : \n")
            field_printer(common_non_standard_response_field, header)
        except Exception:
            print("[-] Failed to fetch Common Non-Standard Response Fields data")

def sub_enum_get_request(subdomain, url):

    get_request = requests.get("http://" + subdomain + "." + url)
    return str(get_request.status_code)

def dir_enum_get_request(dir, url):

    get_request = requests.get("http://" + url + "/" + dir)
    return str(get_request.status_code)

def spider_get_request_content(url):

    get_request = normal_get_request(url)
    response_content = get_request.content
    href_links = re.findall('(?:href=")(.*?)"', response_content.decode(errors="ignore"))
    return href_links

def sub_enum(subdomain, url, verbose):

    try:
        get_request = sub_enum_get_request(subdomain, url)
        if get_request == "200":
            full_url = subdomain + "." + url
            print(Fore.CYAN + "[+] Subdomain exists!        >> " + Style.RESET_ALL + " " + Back.GREEN + full_url + Style.RESET_ALL + " " + Back.BLUE + get_request + " OK " + Style.RESET_ALL)
            subdomain_url_list.append(full_url)
    except requests.exceptions.ConnectionError:
        if verbose == "true" or verbose=="True":
            print(Fore.CYAN + "[-] Subdomain doesn't exist! >> " + Style.RESET_ALL + " " + Back.RED + subdomain + "." + url + " " + Style.RESET_ALL)
            pass
        else:
            pass

def dir_enum(dir, url, verbose):

    try:
        get_request = dir_enum_get_request(dir, url)
        if get_request == "200":
            full_url = url + "/" + dir
            print(Fore.CYAN + "[+] Directory found!         >> " + Style.RESET_ALL + Back.GREEN + "/" + dir + Style.RESET_ALL + " " + Back.BLUE + get_request + " OK " + Style.RESET_ALL)
            directory_url_list.append(full_url)
        else:
            if verbose == "true" or verbose=="True":
                print(Fore.CYAN + "[-] Directory doesn't exist! >> " + Style.RESET_ALL + Back.RED + "/" + dir + Style.RESET_ALL + " " + Back.BLUE + get_request + " " + http_response(get_request) +  " " + Style.RESET_ALL)
                pass
            else:
                pass

    except requests.exceptions.ConnectionError:
        if verbose == "true" or verbose=="True":
            print(Fore.CYAN + "[-] Directory doesn't exist! >> " + Style.RESET_ALL + Back.RED + "/" + dir + Style.RESET_ALL + " " + Back.BLUE + get_request + Style.RESET_ALL)
            pass
        else:
            pass

def spider(url):

    href_links = spider_get_request_content(url)
    for link in href_links:
        link = urlparse.urljoin(url, link)

        if "#" in link:
            link = link.split("#")[0]

        if url in link and link not in url_list:
            url_list.append(link)
            try:
                spider(link)
            except Exception:
                pass
    return url_list

def login_page_detector(url):

    try:
        count = 0
        response = normal_get_request(url)
        content = str(response.content)
        word_list = content.split(">")
        for word in word_list:
            if "<form" in word:
                count += 1
    except Exception:
        pass
    return count

def port_scan_algorithm(url):
    if port_scan == "true":
        try:
            connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(Fore.CYAN + "\n[*] Note : Starting port scan. If CTRL + C does not stop the port scan, use command : pkill python3 in other terminal\n" + Style.RESET_ALL)
            ip = get_ip(url)
            for port in range (0, 65535):
                status = port_scan(ip, port)
                if status == True:
                    print(Fore.RED + "[+] Port " + str(port) + " is open! " + Style.RESET_ALL)
                elif status == False:
                    pass
                connection_socket.close()
            print(Fore.GREEN + "\n[!] Scan completed" + Style.RESET_ALL)
        except KeyboardInterrupt:
            print("[+] CTRL + C detected .... Quitting program")
            connection_socket.close()

def http_response(code):

    response = ""
    if code == "200":
        response = "OK"
    elif code == "301":
        response = "Move Permenantly"
    elif code == "400":
        response = "Bad Request"
    elif code == "404":
        response = "Not Found"
    elif code == "500":
        response = "Internal Server Error"
    else:
        pass
    return response

def line_count(path):

    with open(str(path), "r") as file:
        count = 0
        for line in file:
            if line != "\n":
                count = count + 1
    return count

banner = pyfiglet.figlet_format("     Maverick")
print(Fore.LIGHTGREEN_EX + banner + Style.RESET_ALL)
print(Fore.GREEN + "\033[1m" + "\033[4m" + "Maverick - Website Enumeration and Exploitation Program\n" + "\033[0m" + Style.RESET_ALL)
print(Fore.WHITE + "         -----> By Aditya Patil <-----\n" + Style.RESET_ALL)
print(Fore.RED + "\033[4m" + "[!] Please don't use this program for military or secret service organizations, or for illegal purposes.\n" + Style.RESET_ALL)

options = get_arguements()
url = options.target_url
file = options.wordlist_path
user_mode = options.mode
verbose = options.verbose
ip_mode = options.ip_mode
header_mode = options.header_mode
lgndtc_mode = options.lgndtc_mode
port_scan_option = options.port_scan_option
subdomain_url_list = []
directory_url_list = []
url_list = []

try:

    if ip_mode == "true" or ip_mode == "True" or user_mode == "all":
        try:
            ip = get_ip(url)
            print(Fore.CYAN + "[+] Server IP Address >> " + ip + "\n")
        except Exception:
            print("[-] Couldn't find the IP Address!" + "\n")

    if header_mode:
        http_header_data(url)

    if user_mode == "all":
        header_mode = "all"
        http_header_data(url)

    if user_mode == "sub" or user_mode == "subdomain" or user_mode == "dir" or user_mode == "directory":
        try:
            line_count = line_count(file)
            print(Fore.WHITE + "\nWordlist length : " + str(line_count) + "\n" + Style.RESET_ALL)
        except Exception:
            pass
        with open(str(file), "r") as list:
            try:
                read_file = list.read()
                for word in read_file.split():
                    if user_mode == "sub" or user_mode == "subdomain":
                        sub_enum(word, url, verbose)

                    if user_mode == "dir" or user_mode == "directory":
                        dir_enum(word, url, verbose)
            except Exception:
                pass

    if user_mode == "sub/dir" or user_mode == "all" or user_mode == "subdomain/directory":
        print(Fore.WHITE + "[+] Subdomain Enumeration data : \n" + Style.RESET_ALL)
        with open(str(file), "r") as list:
            try:
                read_file = list.read()
                for word in read_file.split():
                    sub_enum(word, url, verbose)
            except Exception:
                pass
    print("\n")

    if user_mode == "sub/dir" or user_mode == "all" or user_mode == "subdomain/directory":
        print(Fore.WHITE + "[+] Directory Enumeration data : \n" + Style.RESET_ALL)
        with open(str(file), "r") as list:
            try:
                read_file = list.read()
                for word in read_file.split():
                        dir_enum(word, url, verbose)
            except Exception:
                pass

    if user_mode == "spy" or user_mode == "spider" or user_mode == "all":
        print(Fore.WHITE + "\n[+] Data collected by the spider : \n " + Style.RESET_ALL)
        link_list = spider(url)
        for link in link_list:
            print(Style.RESET_ALL + Fore.CYAN + "[+] URL found! >> " + Fore.GREEN + link + Style.RESET_ALL)

        #print("\n")

            form_tag_count = login_page_detector(link)
            if form_tag_count != 0:
                print(Fore.RED + "[+] Potential Login Page detected!  " + Fore.WHITE + "[ " + url + " ] ( " + str(form_tag_count) + " ) <form> tags in the source code." + Style.RESET_ALL)

        try:
            for link in link_list:
                form_tag_count = login_page_detector(link)
                if form_tag_count != 0:
                    print(Fore.RED + "[+] Potential Login Page detected!  " + Fore.WHITE + "[ " + link + " ] ( " + str(form_tag_count) + " ) <form> tags in the source code." + Style.RESET_ALL)
        except Exception:
            pass

    if lgndtc_mode == "true" or lgndtc_mode == "True" or user_mode == "all":

        if user_mode == "sub" or user_mode == "subdomain" or user_mode == "all" or user_mode == "sub/dir" or user_mode == "subdomain/directory":
            try:
                for total_url in subdomain_url_list:
                    counter_lgndtc = login_page_detector(total_url)
                    if counter_lgndtc != 0:
                        print(Fore.RED + "[+] Potential Login Page detected!  " + Fore.WHITE + "[ " + total_url + " ] ( " + str(counter_lgndtc) + " ) <form> tags in the source code." + Style.RESET_ALL)
            except Exception:
                pass

        if user_mode == "dir" or user_mode == "directory" or user_mode == "all" or user_mode == "sub/dir" or user_mode == "subdomain/directory":
            try:
                for total_url in directory_url_list:
                    counter_lgndtc = login_page_detector(total_url)
                    if counter_lgndtc != 0:
                        print(Fore.RED + "[+] Potential Login Page detected!  " + Fore.WHITE + "[ " + total_url + " ] ( " + str(counter_lgndtc) + " ) <form> tags in the source code." + Style.RESET_ALL)
            except Exception:
                pass

    if port_scan_option:
        port_scan_algorithm(url)

except KeyboardInterrupt:
    print("\033[93m" + "\n[!] CTRL + C detected, quiting ...." + "\033[0m")

print(Fore.WHITE + "\n[+] Website Enumeration completed! " + Style.RESET_ALL)

# Make sure to add the port scan file name to the program after adding the serivce identifying function in the program
# I think the OS module will help in this case.
