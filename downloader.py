import argparse
import configparser
import os
from tenable.io import TenableIO
import time

# Create and read configuration file
config_file_name = 'downloader.ini'
config_file_data = """[tenable_io]
########
# Connection info
########
access_key = {{ACCESS_KEY}}
secret_key = {{SECRET_KEY}}
https_proxy =
########
# Scan download options
########
# Scan IDs to download
scan_ids = 100, 101, 102, 103, 104
# Only download scan data if scan completed within x day(s)
# This value should coincide with your timer/cron entry. If the timer/cron entry runs daily then sent this value to 1,
# if the timer/cron entry runs weekly then set this value to 7, etc.
age = 1

[local]
########
# Scan storage options
########
storage_directory = /Users/gg/scans
"""
parser = argparse.ArgumentParser(description='Copy scan data from tenable.io to tenable.sc')
parser_group = parser.add_mutually_exclusive_group(required=True)
parser_group.add_argument('--config', metavar='<tenable.ini>', dest='config_file',
                          help='INI config file')
parser_group.add_argument('--config-gen', dest='config_gen', action='store_true',
                          help='Generate a new INI config file.')
config_file = parser.parse_args().config_file
config_gen = parser.parse_args().config_gen
if config_file:
    if not os.path.isfile(config_file):
        print(config_file + ' does not exist. Use the --config-gen flag to create one.')
        exit()
    else:
        config = configparser.ConfigParser()
        config.read(config_file)
        tio_config = config['tenable_io']
        local_config = config['local']
elif config_gen:
    if os.path.isfile('downloader.ini'):
        print('downloader.ini config file already exists and will NOT be overwritten.\nIf you want to create a new '
              'config file then either rename or delete the existing downloader.ini file.')
        exit()
    else:
        file = open(config_file_name, mode='w')
        file.write(config_file_data)
        file.close()
        if not os.path.isfile(config_file_name):
            print('Unable to write file: ' + config_file_name)
        else:
            print('Wrote file: ' + config_file_name)
        print('Edit the new INI configuration file for your environment.')
        exit()
else:
    print('Input error')
    exit()

# Establish API clients
tio_client = TenableIO(tio_config['access_key'], tio_config['secret_key'])

# Smuggle
scan_ids = tio_config['scan_ids'].replace(' ', '').split(',')
cutoff = int(time.time()) - (int(tio_config['age']) * 86400)
for scan_id in scan_ids:
    print('Scan ID ' + scan_id + ':')
    file_loc = os.path.join(local_config['storage_directory'], scan_id + '.nessus')
    # Download scan from tenable.io
    for scan in tio_client.scans.history(scan_id, limit=1, pages=1):
        if scan['status'] == 'completed' and scan['time_end'] > cutoff:
            print('Downloading scan id ' + scan_id + ' from tenable.io to ' + file_loc)
            with open(file_loc, 'wb') as fobj:
                tio_client.scans.export(scan_id, fobj=fobj)
        else:
            print('This scan is either still running or more than ' + tio_config['age'] +
                  ' days old, as specified in the config file. This scan will not be uploaded to tenable.sc.')
