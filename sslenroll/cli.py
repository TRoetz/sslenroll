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
import cmd

from sslenroll import ca
from sslenroll import db


class Shell(cmd.Cmd):
    def do_list(self, arg):
        for token, id in db.get_last_req_ids():
            print('%s / %s' % (token, id))

    def do_sign(self, token):
        params = db.get_request_params(token)
        if params is None:
            print('Unknown token: %r' % token)
            return
        serial, spki_req_b64, ident = params

        cert = ca.make_cert_for_spki_request(spki_req_b64, serial, ident)
        db.set_certificate(token, base64.b64encode(cert))
        print('Done.')

    def do_quit(self, arg):
        return True
    def do_exit(self, arg):
        return True


if __name__ == '__main__':
    Shell().cmdloop()
