# Webauhn example app

Hi!

This is an example app which implements webauthn passwordless login using the [python-fido2](https://github.com/Yubico/python-fido2) library by Yubico.
It does only implement the authentication pages and two example pages for (not) authenticated users.

The name ``dashboard`` is just some simple name. It does not implement any dashboard like things.

# Setup

The fido2 library does only accept "secure" connections from https. For local deployment you therefore need to create a self signed certificate. If openssl is installed, you can simply run the following command in the project root:
```
openssl req -x509 -out localhost.crt -keyout localhost.key \
 -newkey rsa:2048 -nodes -sha256 \
-subj '/CN=localhost' -extensions EXT -config <( \
printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
```

To install the project you need to have [pipenv](https://github.com/pypa/pipenv) installed. If you have it installed, simply run ``pipenv install``.

To run the server with the self signed certificates (make sure they are named localhost.key and localhost.crt), type ``pipenv run web_secure``.

**Note**: Firefox somehow has a bug when a PIN is required for the security key. Firefox will not ask for the PIN and nothing will happen if you touch you key. You are welcome to open a bug report about this at the [firefox bugtracker](https://bugzilla.mozilla.org/home). This example is tested on Chrome (probably every chromium based browser) and Safari.

Don't forget to setup your ``.env`` file. Simply copy the ``env.example`` and put in your own data.

After that run ``pipenv run migrations`` to setup the tables etc.

# Note

This "project" is for learning purposes. Developing with the fido2 library by Yubico is kind of hard, because they don't have docs (except a bit in the code).
The fido2 library has some own example [here](https://github.com/Yubico/python-fido2/tree/master/examples) (using flask instead of fastapi).

# Contribute

If you found errors or flaws or anything else, open an issue or a pull request. I would be happy :)

To prepare you environment, run ``pipenv install --dev`` and ``pipenv run precommit``. If you want to lint manually, run ``pipenv run lint``.
