'use strict';

let wwaConditionalCreateStarted = false;

// Send an AJAX request and get the response
const wwa_ajax = function () {
    let xmlHttpReq = new XMLHttpRequest();
    return {
        /** Send an AJAX GET request and get the response
         *
         * @param {string} url URL
         * @param {string} data Attached data
         * @param {object} callback Callback function
         */
        get: (url, data = '', callback = () => { }) => {
            xmlHttpReq.open('GET', url + data, true);
            xmlHttpReq.onreadystatechange = () => {
                if (xmlHttpReq.readyState === 4) {
                    callback(xmlHttpReq.responseText.trim(), xmlHttpReq.status >= 200 && xmlHttpReq.status < 300, xmlHttpReq.status);
                }
            }
            xmlHttpReq.send();
        },
        /** Send an AJAX POST request and get the response
         *
         * @param {string} url URL
         * @param {string} data Attached data
         * @param {object} callback Callback function
         */
        post: (url, data = '', callback = () => { }) => {
            xmlHttpReq.open('POST', url, true);
            xmlHttpReq.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
            xmlHttpReq.onreadystatechange = () => {
                if (xmlHttpReq.readyState === 4) {
                    callback(xmlHttpReq.responseText.trim(), xmlHttpReq.status >= 200 && xmlHttpReq.status < 300, xmlHttpReq.status);
                }
            }
            xmlHttpReq.send(data);
        }
    }
};

/** Operate selected DOMs
 *
 * @param {string} selector DOM selector
 * @param {object} callback Callbck function
 * @param {string} method Selecte method
 */
const wwa_dom = (selector, callback = () => { }, method = 'query') => {
    let dom_list = [];
    if (method === 'id') {
        let dom = document.getElementById(selector);
        if (dom) {
            callback(dom);
        }
        return;
    } else if (method === 'class') {
        dom_list = document.getElementsByClassName(selector);
    } else if (method === 'tag') {
        dom_list = document.getElementsByTagName(selector);
    } else {
        dom_list = document.querySelectorAll(selector);
    }
    for (let dom of dom_list) {
        callback(dom);
    }
    return;
}

// Disable all WP-Webauthn buttons
function wwa_disable_buttons() {
    wwa_dom('wwa-test-submit', (dom) => { dom.disabled = true }, 'class');
    wwa_dom('wwa-test-usernameless-submit', (dom) => { dom.disabled = true }, 'class');
    wwa_dom('wwa-bind-submit', (dom) => { dom.disabled = true }, 'class');
    wwa_dom('wwa-login-submit', (dom) => { dom.disabled = true }, 'class');
    wwa_dom('wp-submit', (dom) => { dom.disabled = true }, 'id');
}

// Enable all WP-Webauthn buttons
function wwa_enable_buttons() {
    wwa_dom('wwa-test-submit', (dom) => { dom.disabled = false }, 'class');
    wwa_dom('wwa-test-usernameless-submit', (dom) => { dom.disabled = false }, 'class');
    wwa_dom('wwa-bind-submit', (dom) => { dom.disabled = false }, 'class');
    wwa_dom('wwa-login-submit', (dom) => { dom.disabled = false }, 'class');
    wwa_dom('wp-submit', (dom) => { dom.disabled = false }, 'id');
}

function wwa_maybe_start_conditional_create() {
    if (wwaConditionalCreateStarted || !wwa_php_vars.conditional_create || wwa_php_vars.conditional_create === 'off' || wwa_php_vars.logged_in !== 'true' || !window.isSecureContext) {
        return;
    }
    if (document.getElementsByClassName('wwa-bind-submit').length === 0 && document.getElementsByClassName('wwa-authenticator-list').length === 0) {
        return;
    }
    wwaConditionalCreateStarted = true;

    WWAWebAuthn.supportsConditionalCreate().then((supported) => {
        if (!supported) {
            return;
        }
        const controller = new AbortController();
        WWAWebAuthn.setConditionalCreateAbort(controller);
        let request = wwa_ajax();
        request.get(wwa_php_vars.ajax_url, `?action=wwa_conditional_create_start&_ajax_nonce=${wwa_php_vars._ajax_nonce}`, (rawData, status) => {
            if (!status) {
                return;
            }
            let data;
            try {
                data = JSON.parse(rawData);
            } catch (error) {
                return;
            }
            const clientID = data.clientID;
            const publicKey = WWAWebAuthn.parseCreationOptions(data);
            navigator.credentials.create({ publicKey, signal: controller.signal, mediation: 'conditional' })
                .then(WWAWebAuthn.credentialToJSON)
                .then(JSON.stringify)
                .then((AuthenticatorAttestationResponse) => {
                    let response = wwa_ajax();
                    response.post(`${wwa_php_vars.ajax_url}?action=wwa_conditional_create_response`, `data=${encodeURIComponent(window.btoa(AuthenticatorAttestationResponse))}&clientid=${clientID}&_ajax_nonce=${wwa_php_vars._ajax_nonce}`, (serverData, serverStatus) => {
                        if (!serverStatus) {
                            return;
                        }
                        const parsed = WWAWebAuthn.parseAjaxResponse(serverData);
                        if (parsed.success) {
                            if (parsed.signal && parsed.signal.type === 'currentUserDetails') {
                                WWAWebAuthn.signalCurrentUserDetails(parsed.signal.payload);
                            }
                            updateList();
                        }
                    });
                })
                .catch(() => { });
        });
    }).catch(() => { });
}

function wwa_signal_current_user_details() {
    if (wwa_php_vars.logged_in !== 'true') {
        return;
    }
    WWAWebAuthn.signalCurrentUserDetailsFromEndpoint(wwa_php_vars.ajax_url, wwa_php_vars._ajax_nonce);
}

function wwa_get_login_redirect_intent(button_dom) {
    const form = button_dom.closest('.wwa-login-form');
    const traditionalRedirect = form ? form.querySelector('p.login-submit input[name="redirect_to"]') : null;
    const shortcodeRedirect = form ? form.querySelector('.wwa-redirect-to') : null;
    if (traditionalRedirect) {
        return traditionalRedirect.value;
    }
    if (shortcodeRedirect) {
        return shortcodeRedirect.value;
    }
    return window.location.href;
}

function wwa_get_login_success_redirect(parsed) {
    return parsed.redirect || parsed.redirect_to || '';
}

function wwa_maybe_signal_unknown_credential(parsed) {
    if (parsed.signal && parsed.signal.type === 'unknownCredential') {
        WWAWebAuthn.signalUnknownCredential(parsed.signal.payload);
    }
}

function wwa_get_error_message(error) {
    if (typeof error === 'string') {
        return error;
    }
    if (error && error.responseJSON && typeof error.responseJSON.message === 'string') {
        return error.responseJSON.message;
    }
    if (error && typeof error.responseText === 'string' && error.responseText.trim() !== '') {
        const parsed = WWAWebAuthn.parseAjaxResponse(error.responseText);
        return parsed.message || parsed.raw || error.responseText.trim();
    }
    if (error && typeof error.statusText === 'string' && error.statusText !== '') {
        return error.statusText;
    }
    if (error && typeof error.message === 'string') {
        return error.message;
    }
    return String(error || '');
}

document.addEventListener('DOMContentLoaded', () => {
    wwa_dom('wwa-login-submit', (dom) => { dom.addEventListener('click', wwa_auth, false) }, 'class');
    // If traditional form exists
    if (document.getElementsByClassName('wwa-login-form-traditional').length > 0) {
        wwa_dom('.wwa-login-form-traditional .login-password', (dom) => {
            let height = dom.clientHeight;
            wwa_dom('.wwa-login-form-webauthn .wp-webauthn-notice', (ele) => {
                ele.style.height = height - 40.4 + 'px';
            });
        });
        wwa_dom('wwa-w2t', (dom) => { dom.addEventListener('click', wwa_toggle, false) }, 'class');
        wwa_dom('wwa-t2w', (dom) => { dom.addEventListener('click', wwa_toggle, false) }, 'class');
    } else {
        wwa_dom('.wwa-login-form-webauthn .wp-webauthn-notice', (ele) => {
            ele.style.height = '40.6px';
        });
        wwa_dom('wwa-w2t', (dom) => { dom.parentNode.removeChild(document.getElementsByClassName('wwa-w2t')[0]) }, 'class');
    }
    // If not support
    if (window.PublicKeyCredential === undefined || navigator.credentials.create === undefined || typeof navigator.credentials.create !== 'function') {
        wwa_dom('wwa-test-submit', (dom) => { dom.disabled = true }, 'class');
        wwa_dom('wwa-test-usernameless-submit', (dom) => { dom.disabled = true }, 'class');
        wwa_dom('wwa-bind-submit', (dom) => { dom.disabled = true }, 'class');
        wwa_dom('wwa-show-test', (dom) => { dom.innerText = wwa_php_vars.i18n_31 }, 'class');
        wwa_dom('wwa-show-progress', (dom) => { dom.innerText = wwa_php_vars.i18n_31 }, 'class');
        if (document.getElementsByClassName('wwa-login-form-traditional').length > 0) {
            wwa_dom('wwa-login-form-webauthn', (dom) => { dom.classList.add('wwa-hide-form') }, 'class');
        }
        return;
    }
    wwa_dom('wwa-login-form-traditional', (dom) => { dom.classList.add('wwa-hide-form') }, 'class');
    wwa_dom('wwa-bind-submit', (dom) => { dom.addEventListener('click', wwa_bind, false) }, 'class');
    wwa_dom('wwa-test-submit', (dom) => { dom.addEventListener('click', wwa_verify, false) }, 'class');
    wwa_dom('wwa-test-usernameless-submit', (dom) => { dom.addEventListener('click', wwa_verify, false) }, 'class');
    updateList();
    wwa_maybe_start_conditional_create();
});

// Toggle form
function wwa_toggle(e) {
    e.preventDefault();
    if (document.getElementsByClassName('wwa-login-form-traditional').length > 0) {
        // Disable buttons if it is not shown
        if (document.getElementsByClassName('wwa-login-form-traditional')[0].className.indexOf('wwa-hide-form') !== -1) {
            wwa_dom('wp-submit', (dom) => { dom.disabled = false }, 'id');
            wwa_dom('wwa-login-submit', (dom) => { dom.disabled = true }, 'class');
            setTimeout(() => {
                wwa_dom('user_login', (dom) => { dom.focus() }, 'id');
            }, 0);
        } else {
            wwa_dom('wp-submit', (dom) => { dom.disabled = true }, 'id');
            wwa_dom('wwa-login-submit', (dom) => { dom.disabled = false }, 'class');
            setTimeout(() => {
                wwa_dom('wwa-user-name', (dom) => { dom.focus() }, 'id');
            }, 0);
        }
        document.getElementsByClassName('wwa-login-form-traditional')[0].classList.toggle('wwa-hide-form');
        document.getElementsByClassName('wwa-login-form-webauthn')[0].classList.toggle('wwa-hide-form');
    }
}

// Auth
function wwa_auth() {
    if (window.PublicKeyCredential === undefined || navigator.credentials.create === undefined || typeof navigator.credentials.create !== 'function') {
        alert(wwa_php_vars.i18n_31);
        return;
    }
    let wwa_username = this.closest('.wwa-login-form').getElementsByClassName('wwa-user-name')[0].value;
    if (wwa_username === '' && wwa_php_vars.usernameless !== 'true') {
        alert(wwa_php_vars.i18n_11);
        return;
    }
    WWAWebAuthn.abortConditionalCreate();
    wwa_dom('wwa-user-name', (dom) => { dom.readOnly = true }, 'class');
    wwa_disable_buttons();
    let button_dom = this;
    button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_3;
    let request = wwa_ajax();
    request.get(wwa_php_vars.ajax_url, `?action=wwa_auth_start&user=${encodeURIComponent(wwa_username)}&type=auth`, (rawData, status) => {
        if (status) {
            button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_4;
            let data = rawData;
            try {
                data = JSON.parse(rawData);
            } catch (e) {
                console.warn(rawData);
                wwa_enable_buttons();
                if (wwa_php_vars.usernameless === 'true' && wwa_username === '') {
                    button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7 + wwa_php_vars.i18n_33;
                } else {
                    button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7;
                }
                wwa_dom('wwa-user-name', (dom) => { dom.readOnly = false }, 'class');
                return;
            }
            const clientID = data.clientID;
            data.allowCredentials = WWAWebAuthn.applyAuthenticatorTypeTransports(data.allowCredentials, wwa_php_vars.allow_authenticator_type);
            const publicKey = WWAWebAuthn.parseRequestOptions(data);

            navigator.credentials.get({ 'publicKey': publicKey }).then((credentialInfo) => {
                button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_5;
                return credentialInfo;
            }).then(WWAWebAuthn.credentialToJSON).then(JSON.stringify).then((AuthenticatorResponse) => {
                let response = wwa_ajax();
                response.post(`${wwa_php_vars.ajax_url}?action=wwa_auth`, `data=${encodeURIComponent(window.btoa(AuthenticatorResponse))}&type=auth&clientid=${clientID}&user=${encodeURIComponent(wwa_username)}&remember=${wwa_php_vars.remember_me === 'false' ? 'false' : (document.getElementById('wwa-rememberme') ? (document.getElementById('wwa-rememberme').checked ? 'true' : 'false') : 'false')}&redirect_to=${encodeURIComponent(wwa_get_login_redirect_intent(button_dom))}`, (data, status) => {
                    const parsed = WWAWebAuthn.parseAjaxResponse(data);
                    wwa_maybe_signal_unknown_credential(parsed);
                    if (status) {
                        if (parsed.success) {
                            wwa_enable_buttons();
                            wwa_dom('wwa-user-name', (dom) => { dom.readOnly = false }, 'class');
                            button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_6;
                            const redirectTo = wwa_get_login_success_redirect(parsed);
                            setTimeout(() => {
                                if (redirectTo) {
                                    window.location.href = redirectTo;
                                } else {
                                    window.location.reload();
                                }
                            }, 200);
                        } else {
                            wwa_enable_buttons();
                            if (wwa_php_vars.usernameless === 'true' && wwa_username === '') {
                                button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7 + wwa_php_vars.i18n_33;
                            } else {
                                button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7;
                            }
                            wwa_dom('wwa-user-name', (dom) => { dom.readOnly = false }, 'class');
                        }
                    } else {
                        wwa_enable_buttons();
                        if (wwa_php_vars.usernameless === 'true' && wwa_username === '') {
                            button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7 + wwa_php_vars.i18n_33;
                        } else {
                            button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7;
                        }
                        wwa_dom('wwa-user-name', (dom) => { dom.readOnly = false }, 'class');
                    }
                })
            }).catch((error) => {
                console.warn(error);
                wwa_enable_buttons();
                if (wwa_php_vars.usernameless === 'true' && wwa_username === '') {
                    button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7 + wwa_php_vars.i18n_33;
                } else {
                    button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7;
                }
                wwa_dom('wwa-user-name', (dom) => { dom.readOnly = false }, 'class');
            })
        } else {
            wwa_enable_buttons();
            if (wwa_php_vars.usernameless === 'true' && wwa_username === '') {
                button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7 + wwa_php_vars.i18n_33;
            } else {
                button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7;
            }
            wwa_dom('wwa-user-name', (dom) => { dom.readOnly = false }, 'class');
        }
    })
}

// Bind
function wwa_bind() {
    let button_dom = this;
    let wwa_name = this.parentNode.parentNode.getElementsByClassName('wwa-authenticator-name')[0].value;
    if (wwa_name === '') {
        alert(wwa_php_vars.i18n_12);
        return;
    }
    WWAWebAuthn.abortConditionalCreate();
    const wwa_type_el = this.parentNode.parentNode.getElementsByClassName('wwa-authenticator-type')[0];
    let wwa_type = wwa_type_el ? wwa_type_el.value : (wwa_php_vars.allow_authenticator_type !== 'none' ? wwa_php_vars.allow_authenticator_type : 'none');
    let wwa_usernameless = this.parentNode.parentNode.querySelectorAll('.wwa-authenticator-usernameless:checked')[0] ? this.parentNode.parentNode.querySelectorAll('.wwa-authenticator-usernameless:checked')[0].value : 'false';
    button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_3;
    wwa_disable_buttons();
    // Lock options
    wwa_dom('wwa-authenticator-name', (dom) => { dom.readOnly = true }, 'class');
    wwa_dom('wwa-authenticator-type', (dom) => { dom.disabled = true }, 'class');
    wwa_dom('wwa-authenticator-usernameless', (dom) => { dom.disabled = true }, 'class');
    let request = wwa_ajax();
    request.get(wwa_php_vars.ajax_url, `?action=wwa_create&name=${encodeURIComponent(wwa_name)}&type=${encodeURIComponent(wwa_type)}&usernameless=${wwa_usernameless}&_ajax_nonce=${wwa_php_vars._ajax_nonce}`, (rawData, status) => {
        if (status) {
            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_28;
            let data = rawData;
            try {
                data = JSON.parse(rawData);
            } catch (e) {
                console.warn(rawData);
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_30;
                wwa_enable_buttons();
                wwa_dom('wwa-authenticator-name', (dom) => { dom.readOnly = false }, 'class');
                wwa_dom('wwa-authenticator-type', (dom) => { dom.disabled = false }, 'class');
                wwa_dom('wwa-authenticator-usernameless', (dom) => { dom.disabled = false }, 'class');
                updateList();
                return;
            }
            const clientID = data.clientID;
            const public_key = WWAWebAuthn.parseCreationOptions(data);

            navigator.credentials.create({ 'publicKey': public_key }).then((newCredentialInfo) => {
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_32;
                return newCredentialInfo;
            }).then(WWAWebAuthn.credentialToJSON).then(JSON.stringify).then((AuthenticatorAttestationResponse) => {
                let response = wwa_ajax();
                response.post(`${wwa_php_vars.ajax_url}?action=wwa_create_response`, `data=${encodeURIComponent(window.btoa(AuthenticatorAttestationResponse))}&name=${encodeURIComponent(wwa_name)}&type=${encodeURIComponent(wwa_type)}&usernameless=${wwa_usernameless}&clientid=${clientID}&_ajax_nonce=${wwa_php_vars._ajax_nonce}`, (rawData, status) => {
                    if (status) {
                        const parsed = WWAWebAuthn.parseAjaxResponse(rawData);
                        if (parsed.success) {
                            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_29;
                            wwa_enable_buttons();
                            wwa_dom('wwa-authenticator-name', (dom) => { dom.readOnly = false; dom.value = '' }, 'class');
                            wwa_dom('wwa-authenticator-type', (dom) => { dom.disabled = false }, 'class');
                            wwa_dom('wwa-authenticator-usernameless', (dom) => { dom.disabled = false }, 'class');
                            updateList();
                            wwa_signal_current_user_details();
                        } else {
                            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_30;
                            wwa_enable_buttons();
                            wwa_dom('wwa-authenticator-name', (dom) => { dom.readOnly = false }, 'class');
                            wwa_dom('wwa-authenticator-type', (dom) => { dom.disabled = false }, 'class');
                            wwa_dom('wwa-authenticator-usernameless', (dom) => { dom.disabled = false }, 'class');
                            updateList();
                        }
                    } else {
                        button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_30;
                        wwa_enable_buttons();
                        wwa_dom('wwa-authenticator-name', (dom) => { dom.readOnly = false }, 'class');
                        wwa_dom('wwa-authenticator-type', (dom) => { dom.disabled = false }, 'class');
                        wwa_dom('wwa-authenticator-usernameless', (dom) => { dom.disabled = false }, 'class');
                        updateList();
                    }
                })
            }).catch((error) => {
                console.warn(error);
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_30;
                wwa_enable_buttons();
                wwa_dom('wwa-authenticator-name', (dom) => { dom.readOnly = false }, 'class');
                wwa_dom('wwa-authenticator-type', (dom) => { dom.disabled = false }, 'class');
                wwa_dom('wwa-authenticator-usernameless', (dom) => { dom.disabled = false }, 'class');
                updateList();
            })
        } else {
            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_30;
            wwa_enable_buttons();
            wwa_dom('wwa-authenticator-name', (dom) => { dom.readOnly = false }, 'class');
            wwa_dom('wwa-authenticator-type', (dom) => { dom.disabled = false }, 'class');
            wwa_dom('wwa-authenticator-usernameless', (dom) => { dom.disabled = false }, 'class');
            updateList();
        }
    })
}

// Verify
function wwa_verify() {
    let button_dom = this;
    WWAWebAuthn.abortConditionalCreate();
    button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_3;
    let usernameless = this.className.indexOf('wwa-test-usernameless-submit') === -1 ? false : true;
    wwa_disable_buttons();
    let request = wwa_ajax();
    request.get(wwa_php_vars.ajax_url, `?action=wwa_auth_start&type=test&usernameless=${usernameless ? 'true' : 'false'}`, (rawData, status) => {
        if (status) {
            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_4;
            if (rawData === 'User not inited.') {
                wwa_enable_buttons();
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_15;
                return;
            }
            let data = rawData;
            try {
                data = JSON.parse(rawData);
            } catch (e) {
                console.warn(rawData);
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_15;
                wwa_enable_buttons();
                return;
            }
            const clientID = data.clientID;
            data.allowCredentials = WWAWebAuthn.applyAuthenticatorTypeTransports(data.allowCredentials, wwa_php_vars.allow_authenticator_type);
            const publicKey = WWAWebAuthn.parseRequestOptions(data);

            navigator.credentials.get({ 'publicKey': publicKey }).then((credentialInfo) => {
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_13;
                return credentialInfo;
            }).then((data) => {
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_14;
                return WWAWebAuthn.credentialToJSON(data);
            }).then(JSON.stringify).then((AuthenticatorResponse) => {
                let response = wwa_ajax();
                response.post(`${wwa_php_vars.ajax_url}?action=wwa_auth`, `data=${encodeURIComponent(window.btoa(AuthenticatorResponse))}&type=test&remember=false&clientid=${clientID}`, (rawData, status) => {
                    const parsed = WWAWebAuthn.parseAjaxResponse(rawData);
                    wwa_maybe_signal_unknown_credential(parsed);
                    if (status) {
                        if (parsed.success) {
                            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_16;
                            wwa_enable_buttons();
                            updateList();
                        } else {
                            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_15;
                            wwa_enable_buttons();
                        }
                    } else {
                        button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_15;
                        wwa_enable_buttons();
                    }
                })
            }).catch((error) => {
                console.warn(error);
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_15;
                wwa_enable_buttons();
            })
        } else {
            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_15;
            wwa_enable_buttons();
        }
    })
}

// Update authenticator list
// Compute current number of visible columns for colspan
function getFrontendColspan() {
    let cols = 4; // Identifier, Registered, Last used, Action
    const typeTh = document.getElementsByClassName('wwa-type-th')[0];
    if (typeTh && typeTh.style.display !== 'none') {
        cols++;
    }
    const ulTh = document.getElementsByClassName('wwa-usernameless-th')[0];
    if (ulTh && ulTh.style.display !== 'none') {
        cols++;
    }
    return cols;
}

function setFrontendAuthenticatorListMessage(message) {
    wwa_dom('wwa-authenticator-list', (dom) => {
        dom.textContent = '';
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = getFrontendColspan();
        cell.textContent = message;
        row.appendChild(cell);
        dom.appendChild(row);
    }, 'class');
}

function getFrontendAuthenticatorTypeLabel(item, item_type_disabled) {
    const typeLabel = item.type === 'none' ? wwa_php_vars.i18n_24 : (item.type === 'platform' ? wwa_php_vars.i18n_25 : wwa_php_vars.i18n_26);
    return item_type_disabled ? typeLabel + wwa_php_vars.i18n_35 : typeLabel;
}

function createFrontendAuthenticatorAction(label, handler) {
    const link = document.createElement('a');
    link.href = '#';
    link.textContent = label;
    link.addEventListener('click', (event) => {
        event.preventDefault();
        handler();
    });
    return link;
}

function buildFrontendAuthenticatorRow(item, item_type_disabled) {
    const row = document.createElement('tr');

    const nameCell = document.createElement('td');
    nameCell.textContent = item.name;
    row.appendChild(nameCell);

    if (wwa_php_vars.show_authenticator_type === 'true') {
        const typeCell = document.createElement('td');
        typeCell.className = 'wwa-type-td';
        typeCell.textContent = getFrontendAuthenticatorTypeLabel(item, item_type_disabled);
        row.appendChild(typeCell);
    }

    const addedCell = document.createElement('td');
    addedCell.textContent = item.added;
    row.appendChild(addedCell);

    const lastUsedCell = document.createElement('td');
    lastUsedCell.textContent = item.last_used;
    row.appendChild(lastUsedCell);

    const usernamelessCell = document.createElement('td');
    usernamelessCell.className = 'wwa-usernameless-td';
    usernamelessCell.textContent = item.usernameless ? wwa_php_vars.i18n_1 + (wwa_php_vars.usernameless === 'true' ? '' : wwa_php_vars.i18n_9) : wwa_php_vars.i18n_8;
    row.appendChild(usernamelessCell);

    const actionCell = document.createElement('td');
    actionCell.className = `wwa-key-${item.key}`;
    actionCell.appendChild(createFrontendAuthenticatorAction(wwa_php_vars.i18n_20, () => renameAuthenticator(item.key, item.name)));
    actionCell.appendChild(document.createTextNode(' | '));
    actionCell.appendChild(createFrontendAuthenticatorAction(wwa_php_vars.i18n_27, () => removeAuthenticator(item.key, item.name)));
    row.appendChild(actionCell);

    return row;
}

function updateList() {
    if (document.getElementsByClassName('wwa-authenticator-list').length === 0) {
        return;
    }
    let request = wwa_ajax();
    request.get(wwa_php_vars.ajax_url, `?action=wwa_authenticator_list&_ajax_nonce=${wwa_php_vars._ajax_nonce}`, (rawData, status) => {
        if (status) {
            let data = rawData;
            try {
                data = JSON.parse(rawData);
            } catch (e) {
                console.warn(rawData);
                setFrontendAuthenticatorListMessage(wwa_php_vars.i18n_17);
                return;
            }
            if (data.length === 0) {
                if (wwa_php_vars.usernameless === 'true') {
                    wwa_dom('.wwa-usernameless-th, .wwa-usernameless-td', (dom) => { dom.style.display = 'table-cell' });
                } else {
                    wwa_dom('.wwa-usernameless-th, .wwa-usernameless-td', (dom) => { dom.style.display = 'none' });
                }
                setFrontendAuthenticatorListMessage(wwa_php_vars.i18n_23);
                wwa_dom('wwa-authenticator-list-usernameless-tip', (dom) => { dom.innerText = '' }, 'class');
                wwa_dom('wwa-authenticator-list-type-tip', (dom) => { dom.innerText = '' }, 'class');
                wwa_signal_current_user_details();
                return;
            }
            let has_usernameless = false;
            let has_disabled_type = false;
            const rowItems = [];
            for (const item of data) {
                let item_type_disabled = false;
                if (item.usernameless) {
                    has_usernameless = true;
                }
                if (wwa_php_vars.allow_authenticator_type !== 'none') {
                    if (wwa_php_vars.allow_authenticator_type !== item.type) {
                        has_disabled_type = true;
                        item_type_disabled = true;
                    }
                }
                rowItems.push({ item, item_type_disabled });
            }
            wwa_dom('wwa-authenticator-list', (dom) => {
                dom.textContent = '';
                for (const rowItem of rowItems) {
                    dom.appendChild(buildFrontendAuthenticatorRow(rowItem.item, rowItem.item_type_disabled));
                }
            }, 'class');
            if (has_usernameless || wwa_php_vars.usernameless === 'true') {
                wwa_dom('.wwa-usernameless-th, .wwa-usernameless-td', (dom) => { dom.style.display = 'table-cell' });
            } else {
                wwa_dom('.wwa-usernameless-th, .wwa-usernameless-td', (dom) => { dom.style.display = 'none' });
            }
            if (has_usernameless && wwa_php_vars.usernameless !== 'true') {
                wwa_dom('wwa-authenticator-list-usernameless-tip', (dom) => { dom.innerText = wwa_php_vars.i18n_10 }, 'class');
                wwa_dom('wwa-authenticator-list-usernameless-tip', (dom) => { dom.style.display = 'block'; }, 'class');
            } else {
                wwa_dom('wwa-authenticator-list-usernameless-tip', (dom) => { dom.innerText = ''; dom.style.display = 'none' }, 'class');
            }
            if (has_disabled_type && wwa_php_vars.allow_authenticator_type !== 'none') {
                if (wwa_php_vars.allow_authenticator_type === 'platform') {
                    wwa_dom('wwa-authenticator-list-type-tip', (dom) => { dom.innerText = wwa_php_vars.i18n_36 }, 'class');
                } else {
                    wwa_dom('wwa-authenticator-list-type-tip', (dom) => { dom.innerText = wwa_php_vars.i18n_37 }, 'class');
                }
                wwa_dom('wwa-authenticator-list-type-tip', (dom) => { dom.style.display = 'block'; }, 'class');
            } else {
                wwa_dom('wwa-authenticator-list-type-tip', (dom) => { dom.innerText = ''; dom.style.display = 'none' }, 'class');
            }
            wwa_signal_current_user_details();
        } else {
            setFrontendAuthenticatorListMessage(wwa_php_vars.i18n_17);
        }
    })
}

/** Rename an authenticator
 *
 * @param {string} id Authenticator ID
 * @param {string} name Current authenticator name
 */
function renameAuthenticator(id, name) {
    let new_name = prompt(wwa_php_vars.i18n_21, name);
    if (new_name === '') {
        alert(wwa_php_vars.i18n_12);
    } else if (new_name !== null && new_name !== name) {
        let request = wwa_ajax();
        wwa_dom(`wwa-key-${id}`, (dom) => { dom.innerText = wwa_php_vars.i18n_22 }, 'class');
        request.get(wwa_php_vars.ajax_url, `?action=wwa_modify_authenticator&id=${encodeURIComponent(id)}&name=${encodeURIComponent(new_name)}&target=rename&_ajax_nonce=${wwa_php_vars._ajax_nonce}`, (data, status) => {
            if (status) {
                updateList();
            } else {
                alert(`Error: ${wwa_get_error_message(data)}`);
                updateList();
            }
        })
    }
}

/** Remove an authenticator
 *
 * @param {string} id Authenticator ID
 * @param {string} name Authenticator name
 */
function removeAuthenticator(id, name) {
    if (confirm(wwa_php_vars.i18n_18 + name + (document.getElementsByClassName('wwa-authenticator-list')[0].children.length === 1 ? '\n' + wwa_php_vars.i18n_34 : ''))) {
        wwa_dom(`wwa-key-${id}`, (dom) => { dom.innerText = wwa_php_vars.i18n_19 }, 'class');
        let request = wwa_ajax();
        request.get(wwa_php_vars.ajax_url, `?action=wwa_modify_authenticator&id=${encodeURIComponent(id)}&target=remove&_ajax_nonce=${wwa_php_vars._ajax_nonce}`, (data, status) => {
            if (status) {
                updateList();
            } else {
                alert(`Error: ${wwa_get_error_message(data)}`);
                updateList();
            }
        })
    }
}
