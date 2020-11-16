function b64enc(buf) {
    return base64js.fromByteArray(buf)
                   .replace(/\+/g, "-")
                   .replace(/\//g, "_")
                   .replace(/=/g, "");
}

function b64RawEnc(buf) {
    return base64js.fromByteArray(buf)
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function hexEncode(buf) {
    return Array.from(buf)
                .map(function(x) {
                    return ("0" + x.toString(16)).substr(-2);
				})
                .join("");
}

async function fetch_json(url, options) {
    const response = await fetch(url, options);    
    const body = await response.json();
    if (body.fail)
        throw body.fail;
    return body;
}

/**
 * REGISTRATION FUNCTIONS
 */

/**
 * Callback after the registration form is submitted.
 * @param {Event} e 
 */
const registrationListenerHelper = async (form_id, begin_url, finish_url, e) => {
    e.preventDefault();

    // gather the data in the form
    const form = document.querySelector(form_id);
    const formData = new FormData(form);

    // post the data to the server to generate the PublicKeyCredentialCreateOptions
    let credentialCreateOptionsFromServer;
    try {
        credentialCreateOptionsFromServer = await getCredentialCreateOptionsFromServer(formData, begin_url);
    } catch (err) {
        alert("Failed to generate credential request options: " + err);
        window.location.reload(false);
        return;
    }

    // convert certain members of the PublicKeyCredentialCreateOptions into
    // byte arrays as expected by the spec.
    const publicKeyCredentialCreateOptions = transformCredentialCreateOptions(credentialCreateOptionsFromServer);
    
    // request the authenticator(s) to create a new credential keypair.
    let credential;
    try {
        credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreateOptions
        });
    } catch (err) {
        alert("Error creating credential: " + err);
        window.location.reload(false);
        return;
    }

    // we now have a new credential! We now need to encode the byte arrays
    // in the credential into strings, for posting to our server.
    const newAssertionForServer = transformNewAssertionForServer(credential);

    // post the transformed credential data to the server for validation
    // and storing the public key
    let assertionValidationResponse;
    try {
        assertionValidationResponse = await postNewAssertionToServer(formData, newAssertionForServer, finish_url);
    } catch (err) {
        alert("Server validation of credential failed: " + err);
        window.location.reload(false);
        return;
    }
    
    alert("Succesfully registered as: " + formData.get("registration-email"))

    console.warn("Redirecting to: " + assertionValidationResponse.nexturl)
    window.location.assign(assertionValidationResponse.nexturl);
}

const createRegistrationListener = (form_id, begin_url, finish_url) => {
    async function listener_fn(e) {
        return registrationListenerHelper(form_id, begin_url, finish_url, e);
    }

    return listener_fn;
}

/**
 * Get PublicKeyCredentialRequestOptions for this user from the server
 * formData of the registration form
 * @param {FormData} formData 
 */
const getCredentialRequestOptionsFromServer = async (formData, begin_url) => {
    return await fetch_json(
        begin_url,
        {
            method: "POST",
            body: formData
        }
    );
}

const transformCredentialRequestOptions = (credentialRequestOptionsFromServer) => {
    let {challenge, allowCredentials} = credentialRequestOptionsFromServer;

    challenge = Uint8Array.from(
        atob(challenge.replace(/\_/g, "/").replace(/\-/g, "+")), c => c.charCodeAt(0));

    allowCredentials = allowCredentials.map(credentialDescriptor => {
        let {id} = credentialDescriptor;
        id = id.replace(/\_/g, "/").replace(/\-/g, "+");
        id = Uint8Array.from(atob(id), c => c.charCodeAt(0));
        return Object.assign({}, credentialDescriptor, {id});
    });

    const transformedCredentialRequestOptions = Object.assign(
        {},
        credentialRequestOptionsFromServer,
        {challenge, allowCredentials});

    return transformedCredentialRequestOptions;
};


/**
 * Get PublicKeyCredentialRequestOptions for this user from the server
 * formData of the registration form
 * @param {FormData} formData 
 */
const getCredentialCreateOptionsFromServer = async (formData, begin_url) => {
    return await fetch_json(
        begin_url,
        {
            method: "POST",
            body: formData
        }
    );
}

/**
 * Transforms items in the credentialCreateOptions generated on the server
 * into byte arrays expected by the navigator.credentials.create() call
 * @param {Object} credentialCreateOptionsFromServer 
 */
const transformCredentialCreateOptions = (credentialCreateOptionsFromServer) => {
    let {challenge, user} = credentialCreateOptionsFromServer;
    user.id = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.user.id
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
            ), 
        c => c.charCodeAt(0));

    challenge = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.challenge
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
            ),
        c => c.charCodeAt(0));
    
    const transformedCredentialCreateOptions = Object.assign(
            {}, credentialCreateOptionsFromServer,
            {challenge, user});

    return transformedCredentialCreateOptions;
}



/**
 * AUTHENTICATION FUNCTIONS
 */


/**
 * Callback executed after submitting login form
 * @param {Event} e 
 */
const attestationListenerHelper = async (form_id, begin_url, finish_url, e) => {
    e.preventDefault();
    // gather the data in the form
    const form = document.querySelector(form_id);
    const formData = new FormData(form);

    // post the login data to the server to retrieve the PublicKeyCredentialRequestOptions
    let credentialCreateOptionsFromServer;
    try {
        credentialRequestOptionsFromServer = await getCredentialRequestOptionsFromServer(formData, begin_url);
    } catch (err) {
        alert("Error when getting request options from server: " + err);
        window.location.reload(false);
        return;
    }

    // convert certain members of the PublicKeyCredentialRequestOptions into
    // byte arrays as expected by the spec.    
    const transformedCredentialRequestOptions = transformCredentialRequestOptions(
        credentialRequestOptionsFromServer);

    // request the authenticator to create an assertion signature using the
    // credential private key
    let assertion;
    try {
        assertion = await navigator.credentials.get({
            publicKey: transformedCredentialRequestOptions,
        });
    } catch (err) {
        alert("Error when creating credential: " + err);
        window.location.reload(false);
        return;
    }

    // we now have an authentication assertion! encode the byte arrays contained
    // in the assertion data as strings for posting to the server
    const transformedAssertionForServer = transformAssertionForServer(assertion);

    // post the assertion to the server for verification.
    let response;
    try {
        response = await postAssertionToServer(formData, transformedAssertionForServer, finish_url);
    } catch (err) {
        alert("Error when validating assertion on server: " + err);
        window.location.reload(false);
        return;
    }

    alert("Succesfully attestated request!");

    console.warn("Redirecting to: " + response.nexturl);
    window.location.assign(response.nexturl);
};

const createAttestationListener = (form_id, begin_url, finish_url) => {
    async function listener_fn(e) {
        return attestationListenerHelper(form_id, begin_url, finish_url, e);
    }

    return listener_fn;
}

/**
 * Transforms the binary data in the credential into base64 strings
 * for posting to the server.
 * @param {PublicKeyCredential} newAssertion 
 */
const transformNewAssertionForServer = (newAssertion) => {
    const attObj = new Uint8Array(
        newAssertion.response.attestationObject);
    const clientDataJSON = new Uint8Array(
        newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(
        newAssertion.rawId);

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        attObj: b64enc(attObj),
        clientData: b64enc(clientDataJSON),
    };
}

/**
 * Posts the new credential data to the server for validation and storage.
 * @param {Object} credentialDataForServer 
 */
const postNewAssertionToServer = async (formData, credentialDataForServer, finish_url) => {
    Object.entries(credentialDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });
    
    return await fetch_json(
        finish_url, 
        {
            method: "POST",
            body: formData
        });
}

/**
 * Encodes the binary data in the assertion into strings for posting to the server.
 * @param {PublicKeyCredential} newAssertion 
 */
const transformAssertionForServer = (newAssertion) => {
    const authData = new Uint8Array(newAssertion.response.authenticatorData);
    const clientDataJSON = new Uint8Array(newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(newAssertion.rawId);
    const sig = new Uint8Array(newAssertion.response.signature);

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        authData: b64RawEnc(authData),
        clientData: b64RawEnc(clientDataJSON),
        signature: hexEncode(sig),
    };
};

/**
 * Post the assertion to the server for validation and logging the user in. 
 * @param {Object} assertionDataForServer 
 */
const postAssertionToServer = async (formData, assertionDataForServer, finish_url) => {
    Object.entries(assertionDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });

    return await fetch_json(
        finish_url,
        {
            method: "POST",
            body: formData
        }
    );
}
