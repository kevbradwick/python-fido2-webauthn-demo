import { showError, showSuccess, hideAlerts } from "./alert.mjs";
import * as CBOR from "./cbor.mjs";


export async function authenticate(userId) {
  try {
    let response = await fetch("/api/authenticate", {
      method: "POST",
      body: JSON.stringify({ userId }),
      redirect: "follow",
      headers: { "Content-Type": "application/json" },
    });
    if (!response.ok) {
      return showError("failed to make request");
    }

    const options = CBOR.decode(await response.arrayBuffer());
    const assertion = await navigator.credentials.get(options);
    response = await fetch("/api/authenticate/complete", {
      method: "POST",
      headers: {"Content-Type": "application/cbor"},
      body: CBOR.encode({
        userId: userId,
        credentialId: new Uint8Array(assertion.rawId),
        authenticatorData: new Uint8Array(assertion.response.authenticatorData),
        clientDataJSON: new Uint8Array(assertion.response.clientDataJSON),
        signature: new Uint8Array(assertion.response.signature),
      })
    });

    if (response.ok) {
      hideAlerts();
      showSuccess("Success!");
    }
  } catch (e) {
    showError(e);
  }
}