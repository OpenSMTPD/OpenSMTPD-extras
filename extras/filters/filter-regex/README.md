### DESCRIPTION

Check lists of regular expressions against SMTP session data

### OPTIONS

<dl>

<dt>-c <i>directory</i></dt>
<dd>Directory to chroot into. If used, the following filenames have to be
relative to the chroot directory. Default is not to chroot.</dd>

<dt>-n <i>filename</i></dt>
<dd>Use regular expressions in <i>filename</i> against connecting hostname.
Close connection on match.</dd>

<dt>-h <i>filename</i></dt>
<dd>Use regular expressions in <i>filename</i> against HELO/EHLO string. Answer
with permanent error 530 on match.</dd>

<dt>-m <i>filename</i></dt>
<dd>Use regular expressions in <i>filename</i> against envelope sender. Answer
with permanent error 530 on match.</dd>

<dt>-r <i>filename</i></dt>
<dd>Use regular expressions in <i>filename</i> against envelope recipient.
Answer with permanent error 530 on match.</dd>

<dt>-d <i>filename</i></dt>
<dd>Use regular expressions in <i>filename</i> against mail content (per line).
Answer with permanent error 530 on match.</dd>

<dt>-l <i>number</i></dt>
<dd>Limit number of body lines to match against.</dd>

</dl>

### FORMAT

The files are formatted as one extended regular expression per line with an
optional `!` as first character to exclude the following pattern and exit
without checking further. Example: the hostname list
```
!abc123\.someisp\.com$
\.someisp\.com$
\.otherisp\.com$
```
will allow connections from a single hostname while denying similar hosts. See
[re_format(7)](http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man7/re_format.7?query=re_format&sec=7)
for regular expression details.

