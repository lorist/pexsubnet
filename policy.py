import csv
from netaddr import *
from flask import Flask, jsonify, send_from_directory, request, Response,  url_for, render_template, redirect
from werkzeug import secure_filename
import os
import re
import json
import socket

application = Flask(__name__)

# locations.csv:
# sydney,melbourne,10.61.0.0/24
# melbourne,sydney,10.61.1.0/24
#########Start uploads

# This is the path to the upload directory
application.config['UPLOAD_FOLDER'] = 'csv/'
# These are the extension that we are accepting to be uploaded
application.config['ALLOWED_EXTENSIONS'] = set(['csv'])

# For a given file, return whether it's an allowed type or not
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in application.config['ALLOWED_EXTENSIONS']

# This route will show a form to perform an AJAX request
# jQuery is loaded to execute the request and update the
# value of the operation
@application.route('/')
def index():
    return render_template('index.html')


# Route that will process the file upload
@application.route('/upload', methods=['POST'])
def upload():
    # Get the name of the uploaded file
    file = request.files['file']
    # Check if the file is one of the allowed types/extensions
    if file and allowed_file(file.filename):
        # Make the filename safe, remove unsupported chars
        filename = secure_filename(file.filename)
        # Move the file form the temporal folder to
        # the upload folder we setup
        file.save(os.path.join(application.config['UPLOAD_FOLDER'], filename))
        # Redirect the user to the uploaded_file route, which
        # will basicaly show on the browser the uploaded file
        return redirect(url_for('uploaded_file',
                                filename=filename))

# This route is expecting a parameter containing the name
# of a file. Curr
@application.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(application.config['UPLOAD_FOLDER'],
                               filename)


######### End uploads

class InvalidUsage(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv

class Location(object):
    def __init__(self, ip):
        self.ip = ip

    @property
    def ip(self):
        return self._ip

    ##validate we are getting a valid IP:
    @ip.setter
    def ip(self, v):
        '''Validate an IPv4 address'''
        try:
            socket.inet_aton(v)
            if v.count('.') == 3:
                self._ip = v
                return v
        except socket.error:
            pass
        raise InvalidUsage('{0} is not a valid ipv4 address'.format(v))

    def findLocation(self):
      f = open('csv/locations.csv')
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

@application.errorhandler(InvalidUsage)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response

# @application.route('/')
# def hello():
#   application.logger.info('Someone is browsing to policy root..')
#   return "<h1> Pexip location policy sever </h1>"

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

  if protocol == 'mssip' and ms_addr:
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
