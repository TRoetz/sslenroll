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

import os.path
import yaml


class Config:
    def __init__(self, path):
        self.path = path
        if path and os.path.exists(path):
            self.cfg = yaml.load(open(path))
        else:
            self.cfg = {}

    def _default(self, default, key):
        """Returns cfg[key[0]][key[1]][...] or default if key is missing."""
        val = self.cfg
        for i, component in enumerate(key):
            if not isinstance(val, dict):
                raise ValueError("%s in config should be a dict" %
                                 '/'.join(key[:i + 1]))
            if component in val:
                val = val[component]
            else:
                return default
        return val

    def ca_private_key_path(self):
        return self._default('/etc/sslenroll/ca.key',
                             ('ca', 'private_key_path'))

    def ca_cert_path(self):
        return self._default('/etc/sslenroll/ca.crt',
                             ('ca', 'cert_path'))


# Hotsapped at program startup.
cfg = Config(None)
