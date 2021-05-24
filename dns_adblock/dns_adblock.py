import os
import pathlib
import re
import requests
import shutil

blocklist_domains = [
    'https://pgl.yoyo.org/as/serverlist.php?showintro=0;hostformat=nohtml',
    'http://winhelp2002.mvps.org/hosts.txt',
    'https://mirror1.malwaredomains.com/files/justdomains',
    'https://adaway.org/hosts.txt',
    'https://someonewhocares.org/hosts/hosts',
    # 'https://www.malwaredomainlist.com/hostslist/hosts.txt',
    'http://sysctl.org/cameleon/hosts',
    'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt',
    'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt',
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
]

localhost_domains = [
    'localhost',
    'localhost.localdomain',
    'local',
    '255.255.255.255 broadcasthost',
    '::1 localhost',
    '::1 ip6-localhost ip6-loopback',
    '::1 ip6-localhost',
    '::1 ip6-loopback',
    'fe00::0 ip6-localnet',
    'fe80::1%lo0 localhost',
    'ff00::0 ip6-localnet',
    'ff00::0 ip6-mcastprefix',
    'ff02::1 ip6-allnodes',
    'ff02::2 ip6-allrouters',
    'ff02::3 ip6-allhosts',
    '0.0.0.0',
]


def download_lists(blocklist_directory):
    """Download the blocklist files from blocklist_domains list."""
    list_num = 1
    for domain in blocklist_domains:
        host_file = f'host{list_num}'
        full_path = f'{blocklist_directory}/{host_file}'
        if pathlib.Path(full_path).is_file():
            os.unlink(full_path)
        list_num += 1
        r = requests.get(domain)
        if r.status_code == 200:
            with open(full_path, 'w', encoding='utf8') as f:
                f.write(r.text)
                f.close()


def parse_lists(blocklist_directory, master_blocklist):
    """Cleanup hosts file and merge into master blocklist."""
    master_blocklist_path = f'{blocklist_directory}/{master_blocklist}'
    for host_file in os.scandir(blocklist_directory):
        clean_domains = []
        with open(host_file, 'r') as f:
            for line in f.readlines():
                line = re.sub(r'^0.0.0.0', '', line)
                line = re.sub(r'^127.0.0.1', '', line)
                line = re.sub(r'(?m)^ *#.*\n?', '', line)
                line = re.sub(r'(?m)#.*\n?', '', line)
                line = re.sub(r' www\.', '', line)
                line = re.sub(r'.*\.xn--p1ai$', '', line)
                line = line.strip()
                line = " ".join(line.split())
                clean_domains.append(line)
            f.close()
        clean_list(clean_domains, master_blocklist_path)
    clean_master_blocklist(master_blocklist_path)


def clean_master_blocklist(master_blocklist_path):
    """
    Create final master_blocklist by running sort/uniq. Also, adds
    custom blocklist domains.
    """
    master_blocklist = open(master_blocklist_path, 'r', encoding='utf8')
    blocklist_domains = set(master_blocklist)
    blocklist_domains = sorted(blocklist_domains)
    custom_domain_list = custom_blocklist()
    for line in custom_domain_list:
        blocklist_domains.append(line)
    master_blocklist.close()
    master_blocklist = open(master_blocklist_path, 'w', encoding='utf8')
    master_blocklist.writelines("%s" % i for i in blocklist_domains)
    master_blocklist.close()


def clean_list(clean_domains, master_blocklist_path):
    """Sort/uniq each blocklist host file."""
    master_blocklist = open(master_blocklist_path, 'a', encoding='utf8')
    clean_domains = list(filter(None, clean_domains))
    clean_domains.sort()
    master_blocklist.writelines("%s\n" % i for i in clean_domains
                                if i not in localhost_domains)
    master_blocklist.close()
    return clean_domains


def custom_blocklist():
    """Create list from custom_blocklist.txt."""
    with open('custom_blocklist.txt', 'r') as f:
        custom_domain_list = []
        for line in f.readlines():
            custom_domain_list.append(line)
        f.close()
    return custom_domain_list


def create_zone_file(master_blocklist_path, blocklist_directory):
    """Create BIND Zone file."""
    bind_directory = pathlib.Path('bind')
    bind_directory.mkdir(parents=True, exist_ok=True)
    bind_blocklist_path = f'{bind_directory}/rpz.blocklist'
    bind_blocklist_file = open(bind_blocklist_path, 'w', encoding='utf8')
    bind_blocklist_file.write('$TTL 60\n'
                              '@ IN SOA @ rpz.local. (\n'
                              '2020081600 ;Serial\n'
                              '3600 ;Refresh\n'
                              '1800 ;Retry\n'
                              '604800 ;Expire\n'
                              '43200 ;Minimum TTL\n'
                              ')\n\n'
                              ' NS @\n'
                              ' A 127.0.0.1\n'
                              ' AAAA ::1\n\n'
                             )

    with open(master_blocklist_path, 'r') as f:
        for domain in f.readlines():
            domain = domain.strip()
            bind_blocklist_file.write(f'{domain} CNAME .\n')
        f.close()
    bind_blocklist_file.close()
    cleanup(blocklist_directory, bind_directory, master_blocklist_path)


def cleanup(blocklist_directory, bind_directory, master_blocklist_path):
    """
    Cleanup host[0-9] files and move raw master_blocklist to bind
    directory.
    """
    with os.scandir(blocklist_directory) as host_files:
        for host_file in host_files:
            if host_file.name.startswith('host'):
                os.remove(host_file)
            if host_file.name.startswith('master_'):
                shutil.copy(f'{blocklist_directory}/{host_file.name}',
                            bind_directory)


def main():
    """Create directory and remove master_blocklist file."""
    blocklist_directory = pathlib.Path('blocklists')
    blocklist_directory.mkdir(parents=True, exist_ok=True)
    master_blocklist = 'master_blocklist'
    master_blocklist_path = f'{blocklist_directory}/{master_blocklist}'
    if pathlib.Path(master_blocklist_path).is_file():
        os.unlink(master_blocklist_path)
    download_lists(blocklist_directory)
    parse_lists(blocklist_directory, master_blocklist)
    create_zone_file(master_blocklist_path, blocklist_directory)


if __name__ == "__main__":
    """This is executed when run from the command line."""
    main()
