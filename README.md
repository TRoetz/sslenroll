sslenroll - simple UI for browser SSL client cert enroll support
================================================================

What is that?
-------------

My home web server has both public and private applications available over SSL.
I would like the access to private applications to be painless and transparent,
since after all I'm the target user and I don't want security to be in my way.

Enter SSL client certs. Once an SSL client cert is installed into my browser, I
can use the client cert to authentify and identify the browser, and give it
permission to access a subset of the applications (it doesn't have to be all or
nothing!). But managing the client certs is hard. There is no good UI to add
client certs to browsers, and I need to manually play the role of the CA. That
means my client computer needs to generate a key and a CSR, transmit that CSR
to the CA securely (otherwise the CSR might get altered), then do the signing
myself, then transmit the cert back and figure out how to install it. Oh, and
store something for revocation in case something goes bad (computer gets
stolen, etc.). Not ideal.

Except! TIL: browsers have support for generating keypairs locally, inserting
that keypair into some local browser key storage, uploading enough info from
the key to be used to generate a CSR, and install a certificate they download
from the server! Thanks to StartSSL for showing me that's possible, I would
never have guessed. This is all thanks to the <keygen> HTML5 tag, which was
first introduced in Netscape as part of "Netscape SPKI", a long time ago, in a
galaxy far far away.

So instead of doing that manual CA dance, I can do magic and automation:

1. With an unenrolled browser, go to https://home.mynetwork.net/enroll/
2. Click a button. The "CSR" is sent to the server, and is waiting comfortably
   in a database row.
3. I SSH to the server, run the "Approve" command on that request (after
   checking it is indeed *my* request).
4. With some polling magic, the browser detects that the request has been
   approved. The certificate is auto-downloaded and installed into the browser.

Tech
----

* Bottle, SQLite and PyOpenSSL on the server side.
* Very basic HTML + JQuery on the client side.

Idea bucket list
----------------

* Maybe if someone is already enrolled with a cert that has the ADMIN bit, they
  could approve enrollment requests directly from web?
* How to support changes in permissions? Need re-enroll support for this case.
