# DNS-Adblock
This project generates a zone file for BIND from various blocklists.  The zone file can be used with [RPZ](https://en.wikipedia.org/wiki/Response_policy_zone).

## Updates
The blocklist is updated once a day using Github Actions (coming soon).

## Generate your own blocklist file
To download your own blocklist follow these steps.

### Installation requirements
```
poetry install
```

### Build BIND zone file
```
cd dns_adblock
python dns_adblock.py
```

The BIND blocklist is located in `bind/rpz.blocklist`.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
