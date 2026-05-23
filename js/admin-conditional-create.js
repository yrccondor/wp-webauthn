'use strict';

(() => {
    if (!window.isSecureContext) {
        return;
    }

    let started = false;

    const vars = window.wwa_conditional_create_vars;
    if (!vars || !vars.ajax_url || !vars._ajax_nonce) {
        return;
    }
    if (vars.conditional_create === 'off') {
        return;
    }

    function refreshAuthenticatorList() {
        if (typeof window.updateList === 'function') {
            window.updateList();
        }
    }

    function run() {
        if (started) {
            return;
        }
        started = true;

        WWAWebAuthn.supportsConditionalCreate().then((supported) => {
            if (!supported) {
                return;
            }

            const controller = new AbortController();
            WWAWebAuthn.setConditionalCreateAbort(controller);

            fetch(`${vars.ajax_url}?action=wwa_conditional_create_start&_ajax_nonce=${encodeURIComponent(vars._ajax_nonce)}`)
                .then((response) => {
                    if (!response.ok) {
                        return;
                    }
                    return response.json();
                })
                .then((data) => {
                    if (!data || !data.clientID) {
                        return;
                    }
                    const clientID = data.clientID;
                    const publicKey = WWAWebAuthn.parseCreationOptions(data);
                    return navigator.credentials.create({
                        publicKey,
                        signal: controller.signal,
                        mediation: 'conditional'
                    }).then(WWAWebAuthn.credentialToJSON)
                      .then(JSON.stringify)
                      .then((attestationResponse) => {
                          const body = new URLSearchParams();
                          body.append('data', window.btoa(attestationResponse));
                          body.append('clientid', clientID);
                          body.append('_ajax_nonce', vars._ajax_nonce);
                          return fetch(`${vars.ajax_url}?action=wwa_conditional_create_response`, {
                              method: 'POST',
                              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                              body: body.toString()
                          });
                      })
                      .then((response) => response && response.ok ? response.text() : null)
                      .then((text) => {
                          if (!text) {
                              return;
                          }
                          const parsed = WWAWebAuthn.parseAjaxResponse(text);
                          if (parsed.success && parsed.signal && parsed.signal.type === 'currentUserDetails') {
                              WWAWebAuthn.signalCurrentUserDetails(parsed.signal.payload);
                          }
                          if (parsed.success) {
                              refreshAuthenticatorList();
                          }
                      });
                })
                .catch(() => {});
        }).catch(() => {});
    }

    run();
})();
