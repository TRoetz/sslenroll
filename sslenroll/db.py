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

"""Encapsulates the database operations used by the sslenroll backend."""

import functools
import sqlite3
import uuid

from sslenroll.config import cfg


SCHEMA = '''
CREATE TABLE IF NOT EXISTS certs(
    token TEXT NOT NULL,
    spki_req TEXT NOT NULL,
    ident TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    remote_route TEXT NOT NULL,
    cert TEXT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
'''


@functools.lru_cache(128)
def _get_db():
    """Gets a connection to the sqlite3 database."""
    return sqlite3.connect(cfg.db_path())


def initial_setup():
    """Creates the database if it does not exist yet."""
    db = _get_db()
    db.execute(SCHEMA)
    db.commit()


def store_enroll_request(spki_req, ident, ua, remote_route):
    """Stores params around an enroll request to the database.

    spki_req is the base64 of the NetscapeSPKI request object. The rest is just
    metadata that will be shown at enroll confirmation time.

    Returns a random unique identifier that can be used to check status or
    download certificate.
    """
    db = _get_db()
    req_id = uuid.uuid4().hex
    db.execute('INSERT INTO certs VALUES(?, ?, ?, ?, ?, NULL, 0)',
               (req_id, spki_req, ident, ua, remote_route))
    db.commit()
    return req_id


def get_request_certificate(req_id):
    """Returns the certificate from a request based on its ID.

    If no certificate has been generated yet (request not approved), returns
    None.
    """
    cursor = _get_db().cursor()
    cursor.execute('SELECT cert FROM certs WHERE token=?', (req_id,))
    val = cursor.fetchone()
    if val is None:
        return None
    return val[0]


def get_last_req_ids(n=10):
    """Returns the last N request tokens and idents."""
    cursor = _get_db().cursor()
    cursor.execute('SELECT token, ident FROM certs ORDER BY rowid DESC LIMIT ?',
                   (n,))
    for t in cursor.fetchall():
        yield t


def get_request_params(req_id):
    """Returns the parameters of a given certificate request."""
    cursor = _get_db().cursor()
    cursor.execute('SELECT rowid, spki_req, ident FROM certs WHERE token=?',
                   (req_id,))
    val = cursor.fetchone()
    if val is None:
        return None
    return val


def set_certificate(req_id, cert_b64):
    """Stores a new certificate for a given request."""
    db = _get_db()
    db.execute('UPDATE certs SET cert=? WHERE token=?',
               (cert_b64, req_id))
    db.commit()
