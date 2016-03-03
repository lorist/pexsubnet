from subnets import * #subnets.py
from netaddr import *
from flask import Flask
from flask import request
from flask import Response
import re

application = Flask(__name__)

# Subnet lists imported from subnets.py

@application.route('/')
def hello():
  application.logger.warning('Someone it browsing to policy root..')
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
    application.logger.warning('Request-ID: %s | New Skype call from subnet %s | from: %s, calling: %s', request_id, matched_addr, remote_alias, local_alias)

  elif protocol == 'sip' and rem_addr == '10.61.0.111':
    application.logger.warning('New SIP call via the VCS with remote address %s', rem_addr)
    m = re.match(r'(.+@)(.+)', call_id)
    if m is not None:
      matched_addr = m.group(2)
      application.logger.warning('Request-ID: %s | Matched endpoint according to Call-ID: %s | matched address: %s | remote alias: %s | calling: %s', request_id, call_id, matched_addr, remote_alias, local_alias)

    else:
      matched_addr = '1.1.1.1'
      application.logger.warning('Matched SIP call not coming via VCS.')

  elif protocol == 'webrtc' or 'api' or 'h323':
    matched_addr = rem_addr
    application.logger.warning('Request-ID: %s | Matched WEBRTC call with remote address %s | calling: %s | from: %s', request_id, matched_addr, local_alias, remote_alias)

  syd_match = all_matching_cidrs(matched_addr, syd_list )
  mel_match = all_matching_cidrs(matched_addr, mel_list )
  default_match = all_matching_cidrs(matched_addr, none_list )

  if syd_match:
    application.logger.warning('Allocating to Sydney location %s', syd_match)
    location_response = """
    {
    "status" : "success",
    "result" : {
      "location" : "LAN",
      "primary_overflow_location" : "external"
      }
    }
    """
  elif mel_match:
    application.logger.warning('Allocating to Melbourne location %s', mel_match)
    location_response = """
      {
      "status" : "success",
      "result" : {
        "location" : "external",
        "primary_overflow_location" : "LAN"
        }
      }
      """
  else:
    application.logger.warning('No matching subnet, sending to default location')
    location_response = """
      {
      "status" : "default",
      "result" : {
        "location" : "LAN",
        "primary_overflow_location" : "external"
        }
      }
      """
  application.logger.warning('Sending response: %s', location_response)
  return Response(response=location_response, status=200, mimetype="application/json")

if __name__  ==  '__main__':
    application.run(host = '0.0.0.0')
