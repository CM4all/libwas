The Web Application Socket Protocol
===================================

Author: Max Kellermann <mk@cm4all.com>

*Web Application Socket* is a protocol between a web server and an
application generating dynamic content.  Unlike other protocols such
as (Fast)CGI and AJPv13, it is optimized for fast zero-copy operation.

This repository contains the protocol definition and a reference
implementation written in C.

`Documentation <https://libwas.readthedocs.io/en/latest/>`__
