<div align="center">
<h1>ipstat</h1>
<em>A Linux command-line tool for fetching IP address metadata.</em>
</div>

## Introduction
`ipstat` is a command-line tool written in C intended for use with Linux. It can be used to fetch metadata for any IP address including geographical location, responsible organization, and timezone.

## Compiling and manual installation
First, clone this repository:

```
$ git clone https://github.com/will-hinson/ipstat.git
Cloning into 'ipstat'...
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 10 (delta 0), reused 7 (delta 0), pack-reused 0
Receiving objects: 100% (10/10), 8.93 KiB | 8.93 MiB/s, done.
$ cd ipstat
```

Then, build and install `ipstat`. The `gcc` compiler and GNU Make are required. You will also need to ensure that `libcurl` and `json-c` are installed. The following example is for Arch Linux; you should use the appropriate package manager to install the libraries on your system:

```
$ sudo pacman -S gcc make curl json-c
...
:: Processing package changes...
(1/2) installing curl
(2/2) installing json-c
:: Running post-transaction hooks...
(1/1) Arming ConditionNeedsUpdate...
$ make clean; make
rm -rf build
mkdir -p build
gcc -g -lcurl -ljson-c ipstat.c -o build/ipstat
```

Finally, run `make install` as a superuser. `ipstat` will be installed in /usr/local/bin:

```
$ sudo make install
install build/ipstat /usr/local/bin
$ ipstat 1.1.1.1
Address:       1.1.1.1
Host:          one.one.one.one
Anycast:       Yes
City:          Los Angeles
Region:        California
Country:       US
Location:      34.0522,-118.2437
Organization:  AS13335 Cloudflare, Inc.
Postal code:   90076
Timezone:      America/Los_Angeles
```

## Uninstalling
`make` may also be used to remove `ipstat` by invoking the `uninstall` target as a superuser:

```
$ sudo make uninstall
rm /usr/local/bin/ipstat
```

## Usage

```shell
ipstat [-e endpoint_format] [-h hostname] ip_address
```

`ipstat` may be run with either an IP address or a hostname as its target. If a hostname is provided with `-h`, its IP address will be resolved:

```
$ ipstat 172.217.15.206
Address:       172.217.15.206
Host:          mia09s20-in-f14.1e100.net
Anycast:       No
City:          Miami
Region:        Florida
Country:       US
Location:      25.7743,-80.1937
Organization:  AS15169 Google LLC
Postal code:   33101
Timezone:      America/New_York
$ ipstat -h github.com
Address:       140.82.113.3
Host:          lb-140-82-113-3-iad.github.com
Anycast:       No
City:          South Riding
Region:        Virginia
Country:       US
Location:      38.9209,-77.5039
Organization:  AS36459 GitHub, Inc.
Postal code:   20152
Timezone:      America/New_York
```

Additionally, a different API endpoint format string may be provided using `-e`. The default API endpoint format string is `https://ipinfo.io/{}/json`.

## Acknowledgements
- `ipstat` utilizes the [ipinfo.io API](https://ipinfo.io/) to fetch information regarding IP addresses.
