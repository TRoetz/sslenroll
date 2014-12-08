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

"""Handles all the CA related operations of sslenroll."""

import datetime
import functools
import os.path
import random
import socket

from OpenSSL import crypto

from sslenroll.config import cfg


def netscape_spki_from_b64(b64):
    """Converts a base64 encoded Netscape SPKI DER to a crypto.NetscapeSPKI.

    PyOpenSSL does not yet support doing that by itself, so some work around
    through FFI and "internals-patching" trickery is required to perform this
    conversion. https://github.com/pyca/pyopenssl/issues/177 tracks the issue
    upstream.
    """
    if not hasattr(netscape_spki_from_b64, 'NETSCAPE_SPKI_b64_decode'):
        from cffi import FFI as CFFI
        from OpenSSL._util import ffi as _sslffi, lib as _ssllib
        cffi = CFFI()
        cffi.cdef('void* NETSCAPE_SPKI_b64_decode(const char *str, int len);')
        lib = cffi.dlopen('libssl.so')
        def wrapper(b64, lib=lib):
            if isinstance(b64, str):
                b64 = b64.encode('ascii')
            b64_ptr = _sslffi.new('char[]', b64)
            spki_obj = lib.NETSCAPE_SPKI_b64_decode(b64_ptr, len(b64))
            if spki_obj == cffi.NULL:
                raise ValueError("Invalid SPKI base64")
            def free(spki_obj, ref=b64_ptr):
                _ssllib.NETSCAPE_SPKI_free(spki_obj)
            return _sslffi.gc(spki_obj, free)
        netscape_spki_from_b64.func = wrapper

    ret = crypto.NetscapeSPKI()
    ret._spki = netscape_spki_from_b64.func(b64)
    return ret


def _try_load_ca_private_key(path):
    """Checks that the provided private key is usable and returns it."""
    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, open(path, 'rb').read())
    if pkey.bits() < 2048:
        raise ValueError("I'm sorry Dave, I can't let you use a small "
                         "RSA key.")
    pkey.check()
    return pkey


def _generate_ca_private_key(path):
    """Generates a new private key and saves it to the given path."""
    DEFAULT_KEY_ALG = crypto.TYPE_RSA
    DEFAULT_KEY_BITS = 2048

    pkey = crypto.PKey()
    pkey.generate_key(DEFAULT_KEY_ALG, DEFAULT_KEY_BITS)
    data = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
    open(path, 'wb').write(data)


@functools.lru_cache(None)
def get_ca_private_key():
    """Returns the CA private key as a crypto.PKey object.

    Caches the result forever - we do not support reloading the CA key
    dynamically during runtime, and the global configuration object is not
    expected to change either.
    """
    return _try_load_ca_private_key(cfg.ca_private_key_path())


def _try_load_ca_cert(path):
    """Checks that the provided certificate is usable and returns it."""
    crt = crypto.load_certificate(crypto.FILETYPE_PEM,
            open(path, 'rb').read())
    if crt.has_expired():
        raise ValueError('CA certificate has expired.')
    if crt.get_signature_algorithm() in ('md5', 'sha1'):
        raise ValueError('CA certificate signed with MD5 or SHA1.')
    return crt


def _generate_ca_cert(path, pkey):
    """Generates a new certificate and saves it to the given path."""
    crt = crypto.X509()

    not_before_time = datetime.datetime.now(datetime.timezone.utc)
    not_after_time = not_before_time + datetime.timedelta(days=5000)

    crt.set_notBefore(
            not_before_time.strftime('%Y%m%d%H%M%S%z').encode('ascii'))
    crt.set_notAfter(
            not_after_time.strftime('%Y%m%d%H%M%S%z').encode('ascii'))

    issuer = crt.get_issuer()
    issuer.C = 'XX'
    issuer.ST = 'Internet'
    issuer.O = 'SSLEnroll'
    issuer.CN = socket.gethostname()

    crt.set_issuer(issuer)
    crt.set_subject(issuer)

    crt.set_serial_number(random.randrange(0, 2**64))
    crt.set_pubkey(pkey)
    crt.sign(pkey, 'sha256')

    data = crypto.dump_certificate(crypto.FILETYPE_PEM, crt)
    open(path, 'wb').write(data)


def initial_setup():
    """Generates the CA certificate and keys if not already present."""

    if os.path.exists(cfg.ca_private_key_path()):
        pkey = _try_load_ca_private_key(cfg.ca_private_key_path())
    else:
        pkey = _generate_ca_private_key(cfg.ca_private_key_path())

    if os.path.exists(cfg.ca_cert_path()):
        _try_load_ca_cert(cfg.ca_cert_path())
    else:
        _generate_ca_cert(cfg.ca_cert_path(), pkey)


def spki_req_is_valid(spki_req):
    """Checks if an SPKI request object is properly formatted."""
    try:
        netscape_spki_from_b64(spki_req)
        return True
    except Exception:
        return False
