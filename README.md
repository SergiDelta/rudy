# rudy
Implementation of RUDY (Are you dead yet?) Denial of Service attack in Python.
## Description
RUDY is a "low and slow" attack which generates low traffic in order to make each HTTP POST request last around 10 minutes. It basically fills a form but sends the body of the request byte by byte, waiting several seconds after each one. In this way, we simulate that we are a client with very little bandwith. If we do this distributedly, we may exhaust the available server connections, making it impossible for a legitimate client to connect.
## Usage
```
usage: rudy [-h] [-s SOCKETS] [-t TIME] [-l LENGTH] [-x PROXY] [-v] [--version] url

rudy 1.1 https://github.com/SergiDelta/rudy . Implementation of RUDY (Are you dead yet?)
Denial of Service attack in Python.

positional arguments:
  url                   Absolute path to website, i.e [http[s]://]host[:port][file_path]

optional arguments:
  -h, --help            show this help message and exit
  -s SOCKETS, --sockets SOCKETS
                        Number of sockets (connections) to use. Default is 150.
  -t TIME, --time TIME  Period of time in seconds that the program will wait before
                        performing another round of byte sending. Default is 10.
  -l LENGTH, --length LENGTH
                        Content-Length value (bytes) in HTTP POST request. Default is 64.
  -x PROXY, --proxy PROXY
                        Send requests through a Socks5 proxy, e.g: 127.0.0.1:1080
  -v, --verbose         Give details about actions being performed.
  --version             show program's version number and exit
```
## Example
![usage_example](https://user-images.githubusercontent.com/63166659/131248667-88827dd6-eb02-4322-a329-a4f8f1a0ec01.png)
## Disclaimer
Please, use this code for educational purposes only. I am not responsible for any malicious use that may be made of it.
## License & copyright
© Sergio Garcia Lopez

Licensed under the [MIT License](LICENSE)
