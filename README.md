# netcup-dns-hooks
In this repository you will find hooks which can be used to programatically change the DNS hosted by netcup via their API

# gaining access to the netcup DNS API

Head to your Customercontrolpanel at [www.customercontrolpanel.de] or [www.customercontrolpanel.com] and log in. Click on "Master Data" ("Stammdaten") on the right site and then on ">_ API" on the upper right corner. You can generate an API Key and your API Password here.

# usage

Edit the `config.yml` and enter your own credentials there. Make sure that this file is read-only to your user or root:
```
$ chmod 400 config.yml
```

```
usage: netcup-dns-hook.py [-h] [--cleanup] [--debug] domainname validation

Hooks into the netcup DNS API to set the DNS Record for the ACME challenge.

positional arguments:
  domainname  domain to be modified.
  validation  validation string

optional arguments:
  -h, --help  show this help message and exit
  --cleanup   yes/no
  --debug     Enable debug messages
```

## Hooks for Certbot
Use both the included shell scripts to run certbot for gaining a wildcard cert:

`$ sudo certbot certonly --manual --preferred-challenges=dns --manual-auth-hook /path/to/script/netcup-auth-hook.sh --manual-cleanup-hook /path/to/script/netcup-cleanup-hook.sh -d *.domainname.com`

## known issues

- If you run Certbot too often, Let's Encrypt won't fetch the new entries. Please wait the TTL time in seconds (e.g. TTL=300 means to wait 5 min) before running certbot again. This is not related to netcup, Let's Encrypt nor this suite; It is common behaviour.
