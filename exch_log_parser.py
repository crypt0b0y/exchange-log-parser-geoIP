#!/usr/bin/env python

import collections
import csv
import sys

import GeoIP

# Read IIS server from stdin.
reader = csv.DictReader(
    sys.stdin,
    fieldnames=[
        'date', 'time', 's-ip', 'cs-method', 'cs-uri-stem',
        'cs-uri-query', 's-port', 'cs-username', 'c-ip', 'csUser-Agent',
        'sc-status', 'sc-substatus', 'sc-win32-status', 'time-taken'],
    restkey='field',
    delimiter=' ')

# Load GeoIP DB
gi = GeoIP.open(
    "GeoLiteCity.dat",
    GeoIP.GEOIP_INDEX_CACHE | GeoIP.GEOIP_CHECK_CACHE)

# Initialize output
fields = ['date', 'user', 'type', 'user_agent', 'ip', 'country', 'city']
writer = csv.writer(sys.stdout)
writer.writerow(fields)
OutRecord = collections.namedtuple('OutRecord', fields)

# Check for Activesync, Exchange Web and OWA access
WHITELIST = [
    '/Microsoft-Server-ActiveSync/default.eas',
    '/EWS/Exchange.asmx',
    '/owa/',
]
seen = set()
for line in reader:
    if line["cs-uri-stem"] not in WHITELIST:
        continue

    # Do GeoIP lookup.
    gidata = gi.record_by_name(line['c-ip'])
    if gidata:
        city = gidata['city']
        country = gidata['country_name']
    else:
        city = country = 'Unknown'

    item = OutRecord(
        date=line['date'],
        user=line['cs-username'],
        type=line['cs-uri-stem'],
        user_agent=line['csUser-Agent'],
        ip=line['c-ip'],
        country=country,
        city=city)

    if item in seen:
        continue

    writer.writerow(item)
    seen.add(item)
