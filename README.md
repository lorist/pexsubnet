These are my notes on getting a a python flask policy server running on the Pexip RP/TURN server listening on port 8443 in parallel to the normal webapp listening on port 443.
Notes include the nginx config (added to the pexapp file) and everything we need to do to get it have it run as a service and start at boot.
Cheers,
Dennis

#### Deploy Pexip RP/TURN OVA


To speed up the download of Linux updates for local, apt-update etc. - replace all ‘gb.’ in the the /etc/apt/sources.list file with ‘au.’ - replace ‘gb.' with closest geo location.

```
sudo nano /etc/apt/sources.list
```

If required - TEMP Proxy Access: Once VM is rebooted Proxy will no longer function.
```
sudo export http_proxy='http://DOMAIN\username:password@proxy:port'
sudo export https_proxy='https://DOMAIN\username:password@proxy:port'
```
Follow: https://support.pexip.com/hc/en-us/articles/203598109-RP-TURN-updates-and-housekeeping

SSH into the RP

Install virtual environment for the Flask app:
```
sudo apt-get install python-pip python-dev

sudo pip install virtualenv
```
Create a folder for the policy:
```
mkdir ~/policy
cd ~/policy
```
Create virtual environment for the policy:

`virtualenv policyenv`

Activate the virtual environment:

`source policyenv/bin/activate`

Install the bits we need to run this example:
```
pip install uwsgi flask netaddr
```
Create csv file in the same directory as the policy.py file. 
Format:
primary_location,primary_overflow_location,CIDR
eg: sydney,melbourne, 10.61.0.0/24

Create your policy file:
```
nano policy.py
```
Example:
```python
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
```
To test that the app starts, allow port 5000 (for test) and 8443 (for production) in iptables:

```
sudo nano /etc/iptables/rules.v4
```
Add:
```
-A INPUT -p tcp -m conntrack --ctstate NEW -m tcp --dport 5000 -j ACCEPT
-A INPUT -p tcp -m conntrack --ctstate NEW -m tcp --dport 8443 -j ACCEPT
```
Reload iptables:
```
sudo iptables-restore < /etc/iptables/rules.v4
```
Run the policy server:
```
python policy.py
```
Test by browsing to the server. http://<your-rp-ip>:5000.

or test the location route: http://<your-rp-ip>:5000/policy/v1/participant/location?protocol=webrtc&remote_address=10.61.0.100. If all is well, you should get something like this:
    {
    "status" : "success",
    "result" : {
      "location" : "LAN",
      "primary_overflow_location" : "external"
      }
    }

Stop the policy test:

CRTL + c

Create WSGI entry point:
```
nano ~/policy/wsgi.py
```
Add:
```python
from policy import application
import logging
import logging.handlers
import socket

###Loggin to syslog:
class ContextFilter(logging.Filter):
  hostname = socket.gethostname()

  def filter(self, record):
    record.hostname = ContextFilter.hostname
    return True

f = ContextFilter()
application.logger.addFilter(f)
handler = logging.handlers.SysLogHandler('/dev/log')
formatter = logging.Formatter('%(asctime)s %(hostname)s POLICY SERVER:: %(message)s', datefmt='%b %d %H:%M:%S')
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)
f = ContextFilter()
application.logger.addHandler(handler)

if __name__ == "__main__":
    application.run()
```
If you want to test out that WSGI launches the policy, run the below. You should then be able to browse to http://<your-rp-ip>:5000 and see that it works.
```
uwsgi --socket 0.0.0.0:5000 --protocol=http -w wsgi
```
Create a config file for uWSGI:
```
nano ~/policy/policy.ini
```
Add:
```
[uwsgi]
module = wsgi

master = true
processes = 10

socket = policy.sock
chmod-socket = 660
vacuum = true

die-on-term = true
```
Create upstart script (policy service)
```
sudo nano /etc/init/policy.conf
```
Add:
```
description "uWSGI server instance configured to serve Pexip policy"

start on runlevel [2345]
stop on runlevel [!2345]

setuid pexip
setgid www-data

env PATH=/home/pexip/policy/policyenv/bin
chdir /home/pexip/policy
exec uwsgi --ini policy.ini
```
If auth is required for policy server:

```
sudo apt-get install apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd exampleuser

New password:
Re-type new password:
Adding password for user exampleuser
```
Now uncomment the auth config in the pexapp config below

Configure Nginx to point to the policy server:
```
sudo nano /etc/nginx/sites-enabled/pexapp
```
Add the highlighted bit:
```
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name pex.space 192.168.10.204;
    return 301 https://$host$request_uri;
}
# Policy server:
server {
    listen 8443 ssl;
    server_name pex.space 192.168.10.204;

    #include /etc/nginx/includes/pex-rewrites.conf;
    #include /etc/nginx/includes/pex-ldap.conf;

    ssl_certificate ssl/pexip.pem;
    ssl_certificate_key ssl/pexip.pem;
    ssl_session_timeout 5m;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES256-SHA384:AES256-SHA256:RC4:HIGH:!MD5:!aNULL:!DH:!EDH;
    ssl_prefer_server_ciphers on;

    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location / {
        #auth_basic “Restricted";
        #auth_basic_user_file /etc/nginx/.htpasswd;
        include uwsgi_params;
        uwsgi_pass unix:/home/pexip/policy/policy.sock;
    }
}
server {
    listen 443 ssl;
    server_name pex.space 192.168.10.204;

    include /etc/nginx/includes/pex-rewrites.conf;
    include /etc/nginx/includes/pex-ldap.conf;

    ssl_certificate ssl/pexip.pem;
    ssl_certificate_key ssl/pexip.pem;
    ssl_session_timeout 5m;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES256-SHA384:AES256-SHA256:RC4:HIGH:!MD5:!aNULL:!DH:!EDH;
    ssl_prefer_server_ciphers on;

    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;

    # Redirect from web root to /webrtc
    location / {
        return 301 /webapp;
    }
```
Reboot the PR:
```
sudo reboot
```
Policy server controls:
```
sudo start policy
sudo stop policy
sudo restart policy
```
Browse to the policy server:

Note, you will need to ensure that the RP has a valid certificate. See: https://docs.pexip.com/rp_turn/rpturn_replace_certificate.htm

The policy server will send logs to syslog. Locally this will be in /var/log/syslog.
Example:
```
#tail -f /var/log/syslog
Feb 29 02:26:24 policy policy POLICY SERVER:: Request-ID:  | Matched WEBRTC call with remote address 10.211.55.100 | calling: meet.dennis | from: Dennis
Feb 29 02:26:24 policy policy POLICY SERVER:: Allocating to Sydney location [IPNetwork('10.211.55.0/24')]
Feb 29 02:26:24 policy policy POLICY SERVER:: Sending response:
    {
    "status" : "success",
    "result" : {
      "location" : "LAN",
      "primary_overflow_location" : "external"
      }
    }num
```
More info about uWSGI: https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-uwsgi-and-nginx-on-ubuntu-14-04# pexsubnet
