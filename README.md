# rudy
Implementation of R.U.D.Y (Are you dead yet?) Denial of Service attack in Python.
## Description
RUDY is a "low and slow" attack which generates low traffic in order to make each HTTP POST request last around 10 minutes. It basically fills a form but sends the body of the request byte by byte, waiting several seconds after each one. In this way, we simulate that we are a client with very little bandwith. If we do this distributedly, we may exhaust the available server connections, making it impossible for a legitimate client to connect.
## Usage
Linux:
  
`python3 rudy.py --help`
  
Windows:
  
`python rudy.py --help`
## License & copyright
© Sergio Garcia Lopez

Licensed under the [MIT License](LICENSE)
