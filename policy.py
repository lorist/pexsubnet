import csv
from netaddr import *
from flask import Flask, jsonify, send_from_directory, request, Response,  url_for, render_template, redirect
from werkzeug import secure_filename
import os
import re
# import json
import simplejson as json
import socket

application = Flask(__name__)

# locations.csv:
# sydney,melbourne,brisbane,10.61.0.0/24
# melbourne,sydney,brisbane,10.61.1.0/24
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
        ip_list.append(row[3])
        matched = all_matching_cidrs(self.ip, ip_list)
        if matched:
          locations_results = []
          locations_results.extend([row[0], row[1], row[2]])
          return locations_results
      return None

@application.errorhandler(InvalidUsage)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response

# @application.route('/policy/v1/service/configuration')
# @application.route('/policy/v1/participant/avatar')
@application.route('/policy/v1/participant/location')
def set_location():
  rem_addr = request.args.get('remote_address', '')
  ms_addr = request.args.get('ms-subnet', '')
  protocol = request.args.get('protocol', '')
  local_alias = request.args.get('local_alias', '')
  remote_alias = request.args.get('remote_alias', '')
  matched_addr = ''

  if protocol == 'mssip' and ms_addr:
    matched_addr = ms_addr
    application.logger.info('New Skype call from subnet %s | from: %s, calling: %s', matched_addr, remote_alias, local_alias)
  else:
    application.logger.info('Matched non MSSIP call from %s. Not providing a location', remote_alias)
    result = jsonify({'status': 'policy.reason.no.mssip - Not providing policy for this call'})
    return result

  if matched_addr:
      ip_addr = Location(matched_addr)
      locations = ip_addr.findLocation()

      if locations:
        application.logger.info('Allocating to location %s and overflow %s', locations[0], locations[1])
        result = jsonify({'status': 'success', 'policy.reason.matched': 'Sending MSSIP call to location', 'result': {'primary_overflow_location': locations[1], 'secondary_overflow_location': locations[2], 'location': locations[0]}})
        return result

      else:
        application.logger.info('No matching subnet, sending to default location')
        result = jsonify({'status': 'policy.reason.no.subnetmatch - No matching subnet, sending to default location'})
        return result

  return Response(response=result, status=200, mimetype="application/json")

if __name__  ==  '__main__':
    application.run(host = '0.0.0.0')
