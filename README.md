irssi-otr
=========

LibOTR (http://www.cypherpunks.ca/otr/) support for IRSSI.

**Mailing list**: otr-dev@lists.cypherpunks.ca

First of all, we strongly recommend to set this option to speed up any OTR
commands or sessions.

`/set cmd_queue_speed 1msec`

The default value of irssi is much higher and used to avoid excess flood on IRC
servers. However, with the message size this module is using and rate of a
normal conversation, it seems OK to set this limit. Please inform us if it
causes problems.

Future works is to handle IRC excess flood inside this module.

Requirements
---------

* libotr 4.0.x - [Download
  Link](http://www.cypherpunks.ca/otr/index.php#downloads)

* irssi-dev >= 0.8.15 - [Download Link](http://www.irssi.org/download)

* glib2.0 Development package

* libgcrypt >= 1.5.0

* automake, autoconf, libtool

Installation
---------

Run the following commands to compile and install.

`$ ./bootstrap`

`$ ./configure --prefix="/usr"`

`$ make && make install`

Quick Start
---------

1. `/load otr` in the Irssi main window.
2. Open a chat window with your buddy.
3. `/otr init`, initiate OTR session.

If no key is found for your user and server, the key generation will be
launched.

You should see `OTR: Gone secure` and you are ready to communicate over OTR.

Instructions
---------

To load the OTR module at startup, use the following and make sure
**otr.so** is located in the **modules/** directory of the Irssi home
(usually ~/.irssi).

`echo "load otr" >> ~/.irssi/startup`

Once loaded, we recommend you add the OTR status bar allowing you to see the
OTR state of private conversation.

`/statusbar window add otr`

Possible states are:

* Plaintext
* Finished
* OTR
* OTR (unverified)

#### Key Generation ####

Key generation happens in a separate process and its duration mainly depends
on the available entropy. If **no** key is detected for the current user and server,
the keys will be generated automatically for you. Or else, you can run:

`/otr genkey nickname@server-addr-fqdn`

Once down, you should see a message in the irssi main window indicating
completion.

`OTR: Key generation for <nickname> completed in X seconds. Reloading keys.`

The default OTR policy irssi-otr is now something between manual and
opportunistic. Manual means you have to start it yourself by issuing a `/otr
init` command and opportunistic means both peers send some magic whitespaces
and start OTR once they receive these whitespaces from the other side.

Irssi-otr uses a mode in between where we are not sending whitespaces as an
announcement (as in opportunistic) but we still handle whitespaces if we see it
from the other side. Therefore if your peer uses opportunistic the handshake
should still start automatically once he writes something.

#### Authentication ####

In order to be sure you are communicating with the right person you can do two
things to autenticate him or her.

1. Use a **shared secret** previously decided between both parties or
   exchanged, **ideally** in person. Use the following command to iniate
   or respond to an authentication request.

   `/otr auth SHARED_SECRET`

2. The second method is to use the **[socialist millionaire
   problem](https://en.wikipedia.org/wiki/Socialist_millionaire)** (SMP)
   mechanism which consist of asking the other party a question for which him
   or her will only be able to respond with the correct answer.

   `/otr authq [YOUR QUESTION HERE] SHARED_SECRET`

   And respond with the command on number 1 above.

3. The third way is to trust manually. Exchange your fingerprint with the other
   party over a telephone or GPG-signed email for instance.

   `/otr trust [FP]`

   You can either type this command in the private conversation window of the
   buddy fingerprint you want to trust or enter the **FP** argument which is
   the five parts of the human readable fingerprint available via the `/otr
   contexts` command.

   For example: `/otr trust 487FFADA 5073FEDD C5AB5C14 5BB6C1FF 6D40D48A`

You can abort an ongoing authentication at any time by using this command.

`/otr authabort`

To **distrust** a fingerprint for whatever reason you may have, use the
following command which is like the trust command above.

`/otr distrust [FP]`

To completely **forget** a fingerprint meaning it will be erased from the OTR
fingerprints file. Again, same as trust/distrust command, you can either enter
the five parts of the fingerprint or execute the command in the private
conversation window.

`/otr forget [FP]`

#### Finishing a Session ####

If the window is closed, a **finish** action is triggered informing the other
hand that you have ended the private session. The status bar will indicate
`plaintext` if so.

You can also use the `/otr finish` command to end the OTR session without
closing the window.

If your buddy finishes the session, you will be notified and the status bar
will indicate `finished` in yellow.

#### Other commands ####

* Print the irssi-otr module version.

`/otr version`

* List all OTR contexts and their status.

`/otr contexts`

Irssi Files
---------

In **<irssi-dir>/otr/otr.{key,fp}** you'll find the fingerprints and your
private keys (should you at any point be interested). There is also the
**otr.instag** file which is of no importance for you and used by libotr.

