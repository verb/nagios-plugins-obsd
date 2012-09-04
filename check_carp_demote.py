#!/usr/bin/env python
#
# Copyright (c) 2012 Lee Verberne <lee@blarg.org>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import optparse
import pynagios
import re
import subprocess

class CarpDemotionCheck(pynagios.Plugin):
    int_group = optparse.make_option("--interface-group", dest="int_group",
                                     type="string", default="carp")

    def check(self):
        int_group = self.options.int_group
        try:
            output = subprocess.check_output(('ifconfig', '-g', int_group),
                                             stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            message = "Error finding count: " + e.output.replace('\n', '')
            response = pynagios.response.Response(pynagios.UNKNOWN, message)
        else:
            re_match = re.search(r'carp demote count (\d+)', output)
            if re_match:
                count = int(re_match.group(1))
                message = "%s demote counter is %d" % (int_group, count)
                response = self.response_for_value(count, message)
            else:
                message = "RE could not match output: " + output.replace('\n', '')
                response = pynagios.response.Response(pynagios.UNKNOWN, message)
    
        return response

if __name__ == '__main__':
    CarpDemotionCheck().check().exit()
