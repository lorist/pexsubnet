import csv
from netaddr import *
from flask import Flask
from flask import request
from flask import Response
import re
import json

application = Flask(__name__)

# locations.csv:
# sydney,melbourne,10.61.0.0/24
# melbourne,sydney,10.61.1.0/24

class Location(object):
    def __init__(self, ip):
        self.ip = ip

    def findLocation(self):
      f = open('locations.csv')
      csv_f = csv.reader(f)
      for row in csv_f:
        ip_list = []
        ip_list.append(row[2])
        matched = all_matching_cidrs(self.ip, ip_list)
        if matched:
          locations_results = []
          locations_results.extend([row[0], row[1]])
          return locations_results
      return None

@application.route('/')
def hello():
  application.logger.info('Someone it browsing to policy root..')
  return "<h1> Pexip location policy sever </h1>"

# @application.route('/policy/v1/service/configuration')
# @application.route('/policy/v1/participant/avatar')
@application.route('/policy/v1/participant/location')
def set_location():
  call_id = request.args.get('Call-ID', '')
  rem_addr = request.args.get('remote_address', '')
  ms_addr = request.args.get('ms-subnet', '')
  protocol = request.args.get('protocol', '')
  local_alias = request.args.get('local_alias', '')
  remote_alias = request.args.get('remote_alias', '')
  request_id = request.args.get('Request-Id', '')
  matched_addr = ''

  if protocol == 'mssip':
    matched_addr = ms_addr
    application.logger.info('Request-ID: %s | New Skype call from subnet %s | from: %s, calling: %s', request_id, matched_addr, remote_alias, local_alias)

  elif protocol == 'sip' and rem_addr == '10.61.0.111':
    application.logger.info('New SIP call via the VCS with remote address %s', rem_addr)
    m = re.match(r'(.+@)(.+)', call_id)
    if m is not None:
      matched_addr = m.group(2)
      application.logger.info('Request-ID: %s | Matched endpoint according to Call-ID: %s | matched address: %s | remote alias: %s | calling: %s', request_id, call_id, matched_addr, remote_alias, local_alias)

    else:
      matched_addr = '1.1.1.1'
      application.logger.info('Matched SIP call not coming via VCS.')

  elif protocol == 'webrtc' or 'api' or 'h323':
    matched_addr = rem_addr
    application.logger.info('Request-ID: %s | Matched WEBRTC call with remote address %s | calling: %s | from: %s', request_id, matched_addr, local_alias, remote_alias)

  ip_addr = Location(matched_addr) 
  locations = ip_addr.findLocation()

  if locations:
    application.logger.info('Allocating to location %s and overflow %s', locations[0], locations[1])
    config = {"location": locations[0],
              "primary_overflow_location": locations[1]
              }
    result = { 'status': 'success', 'result': config }
    return json.dumps(result)

  else:
    application.logger.info('No matching subnet, sending to default location')
    config = {"location": "default",
              "primary_overflow_location": "default"
              }
    result = { 'status': 'success', 'result': config }
    return json.dumps(result)
      
  application.logger.info('Sending response: %s', result)
  return Response(response=result, status=200, mimetype="application/json")

if __name__  ==  '__main__':
    application.run(host = '0.0.0.0')
