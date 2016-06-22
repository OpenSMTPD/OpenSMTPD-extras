#
# Copyright (c) 2014 Gilles Chehade <gilles@poolp.org>
#
# Permission to use, copy, modify, and distribute this software for any
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
#

import random
import tempfile
# import time
import os

queue = {}


def generate_msgid():
    while True:
        msgid = random.randint(1, 0xffffffff)
        if msgid not in queue:
            return msgid


def generate_evpid(msgid):
    if msgid not in queue:
        return 0
    while True:
        evpid = random.randint(1, 0xffffffff)
        if evpid not in queue[msgid]:
            return (msgid << 32) | evpid


# message_create must allocate a message entry and return a stricly positive
# 32-bit unique message identifier.
#
def message_create():
    msgid = generate_msgid()
    queue[msgid] = {'envelopes': {}, 'message': None}
    return msgid


# message_commit must write content of "path" into message and return
# either 0 for failure, or 1 for success.
#
def message_commit(msgid, path):
    queue[msgid]['message'] = open(path, 'rb').read()
    os.unlink(path)
    return 1


# message_delete must remove a message and all associate envelopes,
# returns either 0 for failure, or 1 for success
#
def message_delete(msgid):
    del queue[msgid]
    return 1


# message_fd_r must return a readable file descriptor pointing to the
# content of the message, or -1 in case of failure
#
def message_fd_r(msgid):
    tmp = tempfile.TemporaryFile(mode="w+")
    tmp.write(queue[msgid]['message'])
    tmp.flush()
    tmp.seek(0, os.SEEK_SET)
    return os.dup(tmp.fileno())


def message_corrupt():
    return 1


# envelope_create must create an envelope within a message and return a
# 64-bit unique envelope identifier where upper 32-bit == msgid
#
def envelope_create(msgid, envelope):
    evpid = generate_evpid(msgid)
    if evpid == 0:
        return 0
    queue[msgid]['envelopes'][evpid] = envelope
    return evpid


def envelope_delete(evpid):
    msgid = (evpid >> 32) & 0xffffffff
    del queue[msgid]['envelopes'][evpid]
    if len(queue[msgid]['envelopes']) == 0:
        del queue[msgid]
    return 1


# envelope_update  must create an envelope within a message and return a
# 64-bit unique envelope identifier where upper 32-bit == msgid
#
def envelope_update(evpid, envelope):
    queue[(evpid >> 32) & 0xffffffff]['envelopes'][evpid] = envelope
    return 1


def envelope_load(evpid):
    msgid = (evpid >> 32) & 0xffffffff
    if msgid not in queue:
        return 0
    if evpid not in queue[msgid]['envelopes']:
        return 0
    return queue[msgid]['envelopes'][evpid]


def envelope_walk():
    return -1
