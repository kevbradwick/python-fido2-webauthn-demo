import os
from dataclasses import dataclass, field
from typing import List, Optional

from fido2 import cbor
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorAttachment,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
)
from flask import Flask, abort, jsonify, render_template, request, session

app = Flask(__name__)
app.secret_key = os.urandom(32)

_rp = PublicKeyCredentialRpEntity(name="Demo server", id="localhost")
_server = Fido2Server(_rp)


@dataclass
class User:
    user_id: str
    username: str
    display_name: str
    credentials: List[AttestedCredentialData] = field(default_factory=list)

    def json(self):
        return {
            "user_id": self.user_id,
            "username": self.username,
            "display_name": self.display_name,
        }


# in memory store of users
USERS: List[User] = []


def get_user(user_id: str) -> Optional[User]:
    for u in USERS:
        if u.user_id == user_id:
            return u


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/users")
def api_user_list():
    return jsonify([u.json() for u in USERS])


@app.route("/api/register", methods=["POST"])
def api_register():
    """
    Step 1 in the registration process.

    This will register a new public key credential. In a real world application, the user
    will already be authenticated and the user identity will be known as part of the
    request. For the purpose of the demo, you can set the user on the web page form.
    """
    data = request.json or {}
    user_id = data["userId"]
    username = data["userName"]
    display_name = data["displayName"]

    # if the user is not already known, create them and add them to the list then
    # continue with the security key registration process.
    if not (user := get_user(user_id)):
        user = User(user_id, username, display_name)
        USERS.append(user)

    pk_user_entity = PublicKeyCredentialUserEntity(
        username, str.encode(user_id), display_name
    )

    # this will handle the case where the key has already been registered.
    data, state = _server.register_begin(
        pk_user_entity,
        user.credentials,
        user_verification=UserVerificationRequirement.DISCOURAGED,
        authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
    )

    # saves the public key credentials for this user in memory
    session[f"state-{user_id}"] = state

    return cbor.encode(data)


@app.route("/api/register/complete", methods=["POST"])
def api_register_complete():
    """ """
    data = cbor.decode(request.get_data())
    user_id = data["userId"]  # type: ignore
    client_data = CollectedClientData(data["clientDataJSON"])  # type: ignore
    att_obj = AttestationObject(data["attestationObject"])  # type: ignore

    if not (user := get_user(user_id)):
        return abort(404)

    auth_data = _server.register_complete(
        session[f"state-{user_id}"], client_data, att_obj
    )
    if auth_data.credential_data:
        user.credentials.append(auth_data.credential_data)

    return cbor.encode({"status": "ok"})


@app.route("/api/authenticate", methods=["POST"])
def authenticate():
    data = request.json or {}
    user_id = data["userId"]  # type: ignore

    if not (user := get_user(user_id)):
        return abort(404)

    auth_data, state = _server.authenticate_begin(user.credentials)
    session[f"state-{user_id}"] = state
    return cbor.encode(auth_data)


@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    data = cbor.decode(request.get_data())
    user_id = data["userId"]  # type: ignore

    if not (user := get_user(user_id)):
        return abort(404)

    credential_id = data["credentialId"]  # type: ignore
    client_data = CollectedClientData(data["clientDataJSON"])  # type: ignore
    auth_data = AuthenticatorData(data["authenticatorData"])  # type: ignore
    signature = data["signature"]  # type: ignore

    _server.authenticate_complete(
        session.pop(f"state-{user_id}"),
        user.credentials,
        credential_id,  # type: ignore
        client_data,
        auth_data,
        signature,  # type: ignore
    )

    return cbor.encode({"status": "OK"})


def main():
    # app needs to run in SSL in order for fido2 server to pass security checks against
    # the hostname.
    app.run(debug=True, ssl_context="adhoc")


if __name__ == "__main__":
    main()
