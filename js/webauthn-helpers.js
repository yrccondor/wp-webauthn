'use strict';

window.WWAWebAuthn = (() => {
    const base64urlToBase64 = (input) => {
        input = input.replace(/=/g, '').replace(/-/g, '+').replace(/_/g, '/');
        const pad = input.length % 4;
        if (pad) {
            if (pad === 1) {
                throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
            }
            input += new Array(5 - pad).join('=');
        }
        return input;
    };

    const bytesFromBase64url = (input) => Uint8Array.from(window.atob(base64urlToBase64(input)), (c) => c.charCodeAt(0));
    const arrayToBase64String = (array) => {
        let binary = '';
        for (let index = 0; index < array.length; index++) {
            binary += String.fromCharCode(array[index]);
        }
        return btoa(binary);
    };

    const copyOptions = (options) => {
        const copied = Object.assign({}, options);
        delete copied.clientID;
        return copied;
    };

    const ensureRpName = (publicKey) => {
        if (publicKey.rp) {
            const rpName = publicKey.rp.id || publicKey.rp.name || '';
            publicKey.rp = Object.assign({}, publicKey.rp, {
                name: rpName
            });
        }
        return publicKey;
    };

    const parseCreationOptions = (options) => {
        const publicKey = copyOptions(options);
        ensureRpName(publicKey);
        if (window.PublicKeyCredential && typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function') {
            return ensureRpName(PublicKeyCredential.parseCreationOptionsFromJSON(publicKey));
        }

        publicKey.challenge = bytesFromBase64url(publicKey.challenge);
        publicKey.user = Object.assign({}, publicKey.user, {
            id: bytesFromBase64url(publicKey.user.id)
        });
        if (publicKey.excludeCredentials) {
            publicKey.excludeCredentials = publicKey.excludeCredentials.map((item) => Object.assign({}, item, {
                id: bytesFromBase64url(item.id)
            }));
        }
        return publicKey;
    };

    const parseRequestOptions = (options) => {
        const publicKey = copyOptions(options);
        ensureRpName(publicKey);
        if (window.PublicKeyCredential && typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function') {
            return ensureRpName(PublicKeyCredential.parseRequestOptionsFromJSON(publicKey));
        }

        publicKey.challenge = bytesFromBase64url(publicKey.challenge);
        if (publicKey.allowCredentials) {
            publicKey.allowCredentials = publicKey.allowCredentials.map((item) => Object.assign({}, item, {
                id: bytesFromBase64url(item.id)
            }));
        }
        return publicKey;
    };

    const credentialToJSON = (credential) => {
        if (credential && typeof credential.toJSON === 'function') {
            return credential.toJSON();
        }
        const response = credential.response;
        const serialized = {
            id: credential.id,
            type: credential.type,
            rawId: arrayToBase64String(new Uint8Array(credential.rawId)),
            response: {
                clientDataJSON: arrayToBase64String(new Uint8Array(response.clientDataJSON))
            }
        };
        if (response.attestationObject) {
            serialized.response.attestationObject = arrayToBase64String(new Uint8Array(response.attestationObject));
        }
        if (response.authenticatorData) {
            serialized.response.authenticatorData = arrayToBase64String(new Uint8Array(response.authenticatorData));
            serialized.response.signature = arrayToBase64String(new Uint8Array(response.signature));
            serialized.response.userHandle = response.userHandle ? arrayToBase64String(new Uint8Array(response.userHandle)) : null;
        }
        return serialized;
    };

    const parseAjaxResponse = (raw) => {
        if (typeof raw !== 'string') {
            const data = raw && typeof raw.data === 'object' ? raw.data : null;
            return {
                raw,
                json: raw,
                success: !!(raw && (raw.success === true || raw.data === true || (data && data.success === true))),
                signal: raw && (raw.signal || (data && data.signal)),
                redirect: raw && (raw.redirect || raw.redirect_to || (data && (data.redirect || data.redirect_to)) || null),
                redirect_to: raw && (raw.redirect_to || raw.redirect || (data && (data.redirect_to || data.redirect)) || null),
                message: raw && (raw.message || (data && data.message) || null)
            };
        }
        const text = raw.trim();
        try {
            const json = JSON.parse(text);
            const data = json && typeof json.data === 'object' ? json.data : null;
            return {
                raw: text,
                json,
                success: json === true || json.success === true || json.data === true || json.status === 'true' || (data && data.success === true),
                signal: json.signal || (data && data.signal),
                redirect: json.redirect || json.redirect_to || (data && (data.redirect || data.redirect_to)) || null,
                redirect_to: json.redirect_to || json.redirect || (data && (data.redirect_to || data.redirect)) || null,
                message: json.message || (data && data.message) || null
            };
        } catch (e) {
            return { raw: text, json: null, success: text === 'true', signal: null, redirect: null, redirect_to: null, message: null };
        }
    };

    let clientCapabilitiesPromise = null;
    const getClientCapabilities = () => {
        if (!window.PublicKeyCredential || typeof window.PublicKeyCredential.getClientCapabilities !== 'function') {
            return Promise.resolve({});
        }
        if (!clientCapabilitiesPromise) {
            clientCapabilitiesPromise = window.PublicKeyCredential.getClientCapabilities().catch(() => ({}));
        }
        return clientCapabilitiesPromise;
    };

    const hasClientCapability = (capability) => getClientCapabilities()
        .then((capabilities) => !!(capabilities && capabilities[capability]))
        .catch(() => false);

    const signalUnknownCredential = (payload) => {
        if (!payload || !window.PublicKeyCredential || typeof window.PublicKeyCredential.signalUnknownCredential !== 'function') {
            return Promise.resolve(false);
        }
        return hasClientCapability('signalUnknownCredential').then((supported) => {
            if (!supported) {
                return false;
            }
            return Promise.resolve(window.PublicKeyCredential.signalUnknownCredential(payload)).catch(() => false);
        });
    };

    const signalCurrentUserDetails = (payload) => {
        if (!payload || !window.PublicKeyCredential || typeof window.PublicKeyCredential.signalCurrentUserDetails !== 'function') {
            return Promise.resolve(false);
        }
        return hasClientCapability('signalCurrentUserDetails').then((supported) => {
            if (!supported) {
                return false;
            }
            return Promise.resolve(window.PublicKeyCredential.signalCurrentUserDetails(payload)).catch(() => false);
        });
    };

    const signalCurrentUserDetailsFromEndpoint = (ajaxUrl, nonce) => {
        if (!ajaxUrl || !nonce || !window.PublicKeyCredential || typeof window.PublicKeyCredential.signalCurrentUserDetails !== 'function') {
            return Promise.resolve(false);
        }
        return hasClientCapability('signalCurrentUserDetails').then((supported) => {
            if (!supported) {
                return false;
            }
            const request = new XMLHttpRequest();
            request.open('GET', `${ajaxUrl}?action=wwa_current_user_details_signal&_ajax_nonce=${encodeURIComponent(nonce)}`, true);
            request.onreadystatechange = () => {
                if (request.readyState !== 4 || request.status !== 200) {
                    return;
                }
                const parsed = parseAjaxResponse(request.responseText);
                const payload = (parsed.signal && parsed.signal.payload) || (parsed.json && parsed.json.payload) || (parsed.json && parsed.json.data && parsed.json.data.payload);
                signalCurrentUserDetails(payload);
            };
            request.send();
            return true;
        });
    };

    const supportsConditionalCreate = () => {
        if (!window.navigator || !window.navigator.credentials || typeof window.navigator.credentials.create !== 'function') {
            return Promise.resolve(false);
        }
        return hasClientCapability('conditionalCreate');
    };

    const supportsConditionalGet = () => {
        if (!window.navigator || !window.navigator.credentials || typeof window.navigator.credentials.get !== 'function') {
            return Promise.resolve(false);
        }
        return hasClientCapability('conditionalGet');
    };

    let _conditionalCreateController = null;

    const setConditionalCreateAbort = (controller) => {
        _conditionalCreateController = controller;
    };

    const abortConditionalCreate = () => {
        if (_conditionalCreateController) {
            _conditionalCreateController.abort();
            _conditionalCreateController = null;
        }
    };

    const applyAuthenticatorTypeTransports = (allowCredentials, authenticatorType) => {
        if (!allowCredentials || !authenticatorType || authenticatorType === 'none') {
            return allowCredentials;
        }
        return allowCredentials.map((credential) => {
            const updated = Object.assign({}, credential);
            if (authenticatorType === 'cross-platform') {
                updated.transports = ['usb', 'nfc', 'ble', 'hybrid', 'smart-card'];
            } else if (authenticatorType === 'platform') {
                updated.transports = ['internal'];
            }
            return updated;
        });
    };

    return {
        base64urlToBase64,
        arrayToBase64String,
        parseCreationOptions,
        parseRequestOptions,
        credentialToJSON,
        parseAjaxResponse,
        signalUnknownCredential,
        signalCurrentUserDetails,
        signalCurrentUserDetailsFromEndpoint,
        supportsConditionalCreate,
        supportsConditionalGet,
        setConditionalCreateAbort,
        abortConditionalCreate,
        applyAuthenticatorTypeTransports
    };
})();
