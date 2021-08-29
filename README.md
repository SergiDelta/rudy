# rudy
Implementation of R.U.D.Y (Are you dead yet?) Denial of Service attack in Python.
## Description
RUDY is a "low and slow" attack which generates low traffic in order to make each HTTP POST request last around 10 minutes. It basically fills a form but sends the body of the request byte by byte, waiting several seconds after each one. In this way, we simulate that we are a client with very little bandwith. If we do this distributedly, we may exhaust the available server connections, making it impossible for a legitimate client to connect.
## Usage
Linux:
  
`python3 rudy.py --help`
  
Windows:
  
`python rudy.py --help`
## Example
![usage_example](https://user-images.githubusercontent.com/63166659/131248667-88827dd6-eb02-4322-a329-a4f8f1a0ec01.png)
## Disclaimer
Please, use this code for educational purposes only. I am not responsible for any malicious use that may be made of it.
## License & copyright
© Sergio Garcia Lopez

Licensed under the [MIT License](LICENSE)
