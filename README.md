> {This branch includes a service configuration policy to limit bandwidth for callers coming into VMRs via a DMZ/external location}

Policy server that looks up a caller's remote IP in a csv file and allocates a primary and primary_overflow media location associated with the caller's CIDR.

These are my notes on getting a python flask policy server running on the Pexip RP/TURN server listening on port 8443 in parallel to the normal webapp listening on port 443.

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
Download the policy server:

```
git clone https://github.com/lorist/pexsubnet.git
```

Create virtual environment for the policy:
```
cd pexsubnet
virtualenv policyenv
```
Activate the virtual environment:

`source policyenv/bin/activate`

Install the bits we need to run this example:
```
pip install -r requirements.txt
```
Create csv file in the same directory as the policy.py file. 
Format:
primary_location,primary_overflow_location,CIDR
eg: sydney,melbourne, 10.61.0.0/24


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
```
    {
    "status" : "success",
    "result" : {
      "location" : "LAN",
      "primary_overflow_location" : "external"
      }
    }
```
Stop the policy test:

CRTL + c


If you want to test out that WSGI launches the policy, run the below. You should then be able to browse to http://<your-rp-ip>:5000 and see that it works.
```
uwsgi --socket 0.0.0.0:5000 --protocol=http -w wsgi
```


Copy upstart script (policy service)
```
sudo cp policy.conf /etc/init/
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
################## Policy server START ###############################
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
#################Policy server END #########################################
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
