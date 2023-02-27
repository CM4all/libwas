The Web Application Socket Protocol
===================================

Author: Max Kellermann <mk@cm4all.com>

*Web Application Socket* is a protocol between a web server and an
application generating dynamic content.  Unlike other protocols such
as (Fast)CGI and AJPv13, it is optimized for fast zero-copy operation.


Why?
----

Why yet another protocol?

The problem with existing protocols is that all of them are slow.  CGI
suffers from forking overhead.  HTTP is complex and text based.
AJPv13 and FastCGI are packet based, and thus do not allow zero-copy.

The *WAS* protocol is packet based, but opens a dedicated pipe for the
payload (request/response body), to allow direct raw transfer.  The
goal is to have out-of-process web applications while reducing the
multi-process overhead to the theoretical minimum.


Terminology
-----------

The *container* is the web server which receives requests from the
*browser*.  It forwards the request to the *application*.  Its
response is being forwarded back to the *browser*.


Concept
-------

This protocol is built to mimic the semantics of HTTP.  A request has
a method, a URI, headers (name/value pairs) and optionally a body.  A
response has a status code, headers and optionally a body.

Additionally, a request can have application specific "parameters",
a list of name-value pairs.

Similar to FastCGI, the container launches as many application
processes as it needs.  For simplicity, each application process
handles one request at a time (this limitation may be lifted in a
future protocol version, if advantages can be demonstrated).

There are three connections between the container and the application:

* the *control channel* carries metadata, such as request
  method, request and response headers and the response status
* the *output channel* is used to send the raw body of a
  message
* the *input channel* is used to receive the raw body of a
  message

The control channel is an anonymous local socket pair (Unix domain
sockets), while the input/output channels are unidirectional anonymous
pipes.  Pipes were chosen because the Linux kernel is especially
optimized for zero-copy from and to pipes (using the :samp:`splice()`
system call).


Portability
-----------

This protocol was designed with optimizations for the Linux kernel in
mind.  It is possible to implement it on other operating systems, but
some of the protocol's advantages may not be available.  Other kernels
may offer zero-copy system calls similar to :samp:`splice()`, and
utilizing those may require an amendment to this protocol
specification.

Transferring WAS over the network is not intended.  Therefore, byte
ordering and other platform dependent differences do not apply - all
values are sent in host byte order.


Reference
---------

Lifecycle of an application process
```````````````````````````````````

The container may launch any number of application processes at any
time.  The application should be able to handle an arbitrary number of
consecutive requests.  Implementation of an "idle timeout" should be
left to the container.  When the container does not need the
application anymore, it closes the control socket.  A well-implemented
application exits upon receiving end-of-file on the control socket,
without the need for :envvar:`SIGTERM` and :envvar:`SIGKILL`.

States of an application process
````````````````````````````````

* idle, waiting for a request
* receiving request metadata
* receiving the request body, processing request, sending the
  response
* flushing buffers (optional, see below)

Lifecycle of a request
``````````````````````

After initialization, the application waits for requests on the
control socket.  It does not need to monitor the pipes at this point.

The container first sends :envvar:`REQUEST`, then request metadata
(method, URI, headers).  This is completed by either a :envvar:`DATA`
or a :envvar:`NO_DATA` packet.  :envvar:`NO_DATA` indicates that no
request body is available.  :envvar:`DATA` is the opposite, and in
this case, the container starts sending it to its output pipe (the
application's input pipe).

The application sends response metadata (status code, headers),
followed by either :envvar:`DATA` or :envvar:`NO_DATA`.  After that, it
(optionally) starts sending the response body to its output pipe (the
container's input pipe).

An entity (request or response) is finished when the body transfer was
completed, or when the :envvar:`NO_DATA` was transferred.  Except for
:envvar:`NO_DATA`, there is no special "end" packet.

The data channel
````````````````

After one party has announced a "body" with a :envvar:`DATA` packet,
it starts sending its contents on the according data channel.  As soon
as it knows the total length of the body, a :envvar:`LENGTH` packet
follows.  That may well be after sending is complete.

If the receiver does not want it (but wants to continue handling the
request), it sends a :envvar:`STOP` packet as soon as possible.  The
sender responds with a :envvar:`PREMATURE` packet, announcing the number
of bytes it has sent so far, to allow the receiver to flush the pipe
buffer reliably.  This allows reusing the pipe for the next request.

The control channel protocol
````````````````````````````

Format
''''''

Information on the control channel is enclosed in packets.  A packet
consists of a command, and an optional payload.  The header is defined
by the following C declaration::

  struct was_header {
      uint16_t length;
      uint16_t command;
  };

:envvar:`length` is the length of the payload in bytes.  If the
payload length is not a multiple of 4, it is padded.  This padding is
not included in the :envvar:`length` attribute.

All numbers are in host byte order.  That includes the packet payload,
if applicable.

Request packets
'''''''''''''''

* :envvar:`REQUEST`: start of a HTTP request
* :envvar:`METHOD`: The HTTP request method; payload is a
  :envvar:`uint16_t` with integer values from the :file:`libcm4all-http`
  enumeration type :envvar:`http_method`.  If this packet is not
  received, the application assumes that the method is :envvar:`GET`.
* :envvar:`URI`: the HTTP request URI
* :envvar:`SCRIPT_NAME`: the relevant part of the URI which refers to
  the WAS application
* :envvar:`PATH_INFO`: the tail of the URI after
  :envvar:`SCRIPT_NAME`, not including the query string (and the
  question mark)
* :envvar:`QUERY_STRING` & the query string, i.e. the tail or the URI
  after the question mark (excluding the question mark itself)
* :envvar:`PARAMETER`: an application-defined parameter: a name-value
  pair, separated by a "=" character
* :envvar:`METRIC`: enable metrics, i.e. ask the application to
  provide counters in :envvar:`METRIC` response packets.  No payload.

Response packets
''''''''''''''''

* :envvar:`STATUS`: start of a HTTP request; payload is a
  :envvar:`uint16_t` with integer values from the :path:`libcm4all-http`
  enumeration type :envvar:`http_status`
* :envvar:`METRIC`: provide one metric.  Payload is a 32 bit floating
  point counter value followed by a symbolic name (ASCII letters,
  digits, underscore; without null-terminator).

Common packets
''''''''''''''

* :envvar:`HEADER`: a request or response header: a name-value pair,
  separated by a "=" character
* :envvar:`NO_DATA`: no body present, this entity is finished
* :envvar:`DATA`: a body is present, the length will be announced as
  soon as it is known
* :envvar:`LENGTH`: announces the body length; payload is a
  :envvar:`uint64_t`
* :envvar:`STOP`: asks the communication partner to stop sending the
  body
* :envvar:`PREMATURE`: announces the premature end of the body; packet
  includes the total number of bytes sent to the data pipe
  (:envvar:`uint64_t`)

The Multi Protocol
``````````````````

Some WAS programs can handle multiple WAS connections; for example,
they could handle each connection per thread or they could be
non-blocking and thus be able to handle multiple concurrent requests.
Doing so would save some overhead of spawning one WAS process per
concurrent request.

A Multi-WAS program is launched with an unidirectional ``AF_LOCAL`` /
``SOCK_SEQPACKET`` socket as file descriptor 0.  On this socket, the
WAS process receives ``MULTI_WAS_COMMAND_NEW`` packets with three file
descriptors: control socket, input pipe and output pipe of a new WAS
connection.  The Multi-WAS program starts receiving requests on this
new WAS connection until its control socket is closed (as usual).

The Multi-WAS process exits when its initial socket gets closed by the
peer.
