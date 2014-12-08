# Copyright 2014 delroth, All rights reserved,
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import os.path

import bottle

from sslenroll import ca
from sslenroll import db
from sslenroll.config import cfg

def home():
    params = {
        'register_url': bottle.url('register'),
    }
    return bottle.template('enroll_form', params)


def register():
    ident = bottle.request.forms.get('ident')
    spki_req = bottle.request.forms.get('spki_req')

    # Store some metadata about the request.
    ua = bottle.request.headers.get('User-Agent')
    remote_route = ','.join(bottle.request.remote_route)

    # Check that the spki_req is valid.
    if not ca.spki_req_is_valid(spki_req):
        bottle.abort(400, 'Invalid SPKI request')

    req_id = db.store_enroll_request(spki_req, ident, ua, remote_route)

    dest_url = bottle.url('register_done', req_id=req_id)
    return bottle.redirect(dest_url)


def register_done(req_id):
    params = {
        'check_url': bottle.url('check_status', req_id=req_id),
    }
    return bottle.template('register_done', params)


def check_status(req_id):
    enrolled = db.get_request_certificate(req_id) is not None
    return {'enrolled': db.get_request_certificate(req_id) is not None,
            'cert_url': bottle.url('get_cert', req_id=req_id)}


def get_cert(req_id):
    cert = db.get_request_certificate(req_id)
    if cert is None:
        bottle.abort(403, 'No cert for you')
    else:
        bottle.response.content_type = 'application/x-x509-user-cert'
        return base64.b64decode(cert)


def make_bottle_app():
    base = cfg.web_base_path()
    if not base.startswith('/'):
        base = '/' + base

    app = bottle.default_app()
    app.route(os.path.join(base, ''), 'GET', home, 'home')
    app.route(os.path.join(base, 'register'), 'POST', register, 'register')
    app.route(os.path.join(base, 'register_done/<req_id>'), 'GET',
              register_done, 'register_done')
    app.route(os.path.join(base, 'check/<req_id>'), 'GET', check_status,
              'check_status')
    app.route(os.path.join(base, 'cert/<req_id>'), 'GET', get_cert,
              'get_cert')
    return app

# Load templates from our package path.
bottle.TEMPLATE_PATH.append(os.path.join(os.path.dirname(__file__),
                                         'templates'))

# Needs to exist at toplevel for WSGI compatibility.
app = make_bottle_app()

if __name__ == '__main__':
    # For test/debugging purposes. Do not use in production.
    bottle.debug(True)
    app.run(host='localhost', port=8080)
