# WebAuthn Demo

A demo application that uses the WebAuthn API to register and authenticate users using the FIDO2 protocol used by hardware security keys.

## Quick start

Using [Poetry](https://python-poetry.org/), install the dependencies;

    poetry install

Start the server

    make run

Open up the webapp [https://localhost:5000](https://localhost:5000). The browser will complain about the SSL certificate but you can safely ignore the message.
