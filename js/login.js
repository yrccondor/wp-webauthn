'use strict';

const wwa_passkey_notice_svg = '<svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" style="enable-background:new 0 0 216 216;width:28px" viewBox="0 0 216 216"><style>.st2{fill-rule:evenodd;clip-rule:evenodd}</style><g id="Isolation_Mode"><path d="M0 0h216v216H0z" style="fill:none"/><path d="M172.32 96.79c0 13.78-8.48 25.5-20.29 29.78l7.14 11.83-10.57 13 10.57 12.71-17.04 22.87-12.01-12.82V125.7c-10.68-4.85-18.15-15.97-18.15-28.91 0-17.4 13.51-31.51 30.18-31.51 16.66 0 30.17 14.11 30.17 31.51zm-30.18 4.82c4.02 0 7.28-3.4 7.28-7.6 0-4.2-3.26-7.61-7.28-7.61s-7.28 3.4-7.28 7.61c-.01 4.2 3.26 7.6 7.28 7.6z" style="fill-rule:evenodd;clip-rule:evenodd;fill:#353535"/><path d="M172.41 96.88c0 13.62-8.25 25.23-19.83 29.67l6.58 11.84-9.73 13 9.73 12.71-17.03 23.05v-85.54c4.02 0 7.28-3.41 7.28-7.6 0-4.2-3.26-7.61-7.28-7.61V65.28c16.73 0 30.28 14.15 30.28 31.6zM120.24 131.43c-9.75-8-16.3-20.3-17.2-34.27H50.8c-10.96 0-19.84 9.01-19.84 20.13v25.17c0 5.56 4.44 10.07 9.92 10.07h69.44c5.48 0 9.92-4.51 9.92-10.07v-11.03z" class="st2"/><path d="M73.16 91.13c-2.42-.46-4.82-.89-7.11-1.86-8.65-3.63-13.69-10.32-15.32-19.77-1.12-6.47-.59-12.87 2.03-18.92 3.72-8.6 10.39-13.26 19.15-14.84 5.24-.94 10.46-.73 15.5 1.15 7.59 2.82 12.68 8.26 15.03 16.24 2.38 8.05 2.03 16.1-1.56 23.72-3.72 7.96-10.21 12.23-18.42 13.9-.68.14-1.37.27-2.05.41-2.41-.03-4.83-.03-7.25-.03z" style="fill:#141313"/></g></svg>';
const wwa_passkey_btn_svg = '<svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" style="enable-background:new 0 0 216 216;width:28px" viewBox="0 0 216 216"><style>.st2{fill-rule:evenodd;clip-rule:evenodd}</style><g id="Isolation_Mode"><path d="M0 0h216v216H0z" style="fill:none"/><path d="M172.32 96.79c0 13.78-8.48 25.5-20.29 29.78l7.14 11.83-10.57 13 10.57 12.71-17.04 22.87-12.01-12.82V125.7c-10.68-4.85-18.15-15.97-18.15-28.91 0-17.4 13.51-31.51 30.18-31.51 16.66 0 30.17 14.11 30.17 31.51zm-30.18 4.82c4.02 0 7.28-3.4 7.28-7.6 0-4.2-3.26-7.61-7.28-7.61s-7.28 3.4-7.28 7.61c-.01 4.2 3.26 7.6 7.28 7.6z" style="fill-rule:evenodd;clip-rule:evenodd;fill:currentcolor"/><path d="M172.41 96.88c0 13.62-8.25 25.23-19.83 29.67l6.58 11.84-9.73 13 9.73 12.71-17.03 23.05v-85.54c4.02 0 7.28-3.41 7.28-7.6 0-4.2-3.26-7.61-7.28-7.61V65.28c16.73 0 30.28 14.15 30.28 31.6zM120.24 131.43c-9.75-8-16.3-20.3-17.2-34.27H50.8c-10.96 0-19.84 9.01-19.84 20.13v25.17c0 5.56 4.44 10.07 9.92 10.07h69.44c5.48 0 9.92-4.51 9.92-10.07v-11.03z" class="st2" style="fill:currentcolor"/><path d="M73.16 91.13c-2.42-.46-4.82-.89-7.11-1.86-8.65-3.63-13.69-10.32-15.32-19.77-1.12-6.47-.59-12.87 2.03-18.92 3.72-8.6 10.39-13.26 19.15-14.84 5.24-.94 10.46-.73 15.5 1.15 7.59 2.82 12.68 8.26 15.03 16.24 2.38 8.05 2.03 16.1-1.56 23.72-3.72 7.96-10.21 12.23-18.42 13.9-.68.14-1.37.27-2.05.41-2.41-.03-4.83-.03-7.25-.03z" style="fill:currentcolor"/></g></svg>';

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

let wwaSupported = true;
let wwa_conditional_ui_abort = null;
let wwa_conditional_ui_active = false;

/**
 * Start a Conditional UI (passkey autofill) request.
 * The browser will show a passkey picker in the username autocomplete dropdown.
 * Aborted automatically when the user manually triggers a normal WebAuthn check.
 */
function wwa_start_conditional_ui() {
    if (wwa_conditional_ui_active) return;
    if (!window.PublicKeyCredential) return;

    WWAWebAuthn.supportsConditionalGet().then((available) => {
        if (!available) return;

        wwa_conditional_ui_active = true;
        wwa_conditional_ui_abort = new AbortController();
        const signal = wwa_conditional_ui_abort.signal;

        // Request an empty-user challenge (usernameless style: no allowCredentials)
        let startReq = wwa_ajax();
        startReq.get(wwa_login_php_vars.ajax_url,
            '?action=wwa_auth_start&type=auth&usernameless=true&conditional=true',
            (rawData, status) => {
                if (!status || signal.aborted) {
                    wwa_conditional_ui_active = false;
                    return;
                }
                let data;
                try {
                    data = JSON.parse(rawData);
                } catch (e) {
                    wwa_conditional_ui_active = false;
                    return;
                }

                const clientID = data.clientID;
                const publicKey = WWAWebAuthn.parseRequestOptions(data);

                navigator.credentials.get({
                    publicKey: publicKey,
                    mediation: 'conditional',
                    signal: signal
                }).then((credentialInfo) => {
                    if (!credentialInfo) {
                        wwa_conditional_ui_active = false;
                        return;
                    }
                    // Show authenticating state
                    wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_5; }, 'class');
                    wwa_dom('user_login', (dom) => { dom.readOnly = true; }, 'id');
                    wwa_dom('#wp-webauthn-check, #wp-webauthn', (dom) => { dom.disabled = true; });

                    const AuthenticatorResponse = JSON.stringify(WWAWebAuthn.credentialToJSON(credentialInfo));
                    // The server needs the usernameless path, so username is empty
                    const userField = document.getElementById('user_login');
                    const username = userField ? userField.value : '';

                    let response = wwa_ajax();
                    response.post(
                        `${wwa_login_php_vars.ajax_url}?action=wwa_auth`,
                        `data=${encodeURIComponent(window.btoa(AuthenticatorResponse))}&type=auth&clientid=${clientID}&user=${encodeURIComponent(username)}&conditional=true&remember=${wwa_login_php_vars.remember_me === 'false' ? 'false' : (document.getElementById('rememberme') ? (document.getElementById('rememberme').checked ? 'true' : 'false') : 'false')}&redirect_to=${encodeURIComponent(getLoginRedirectIntent())}` ,
                        (resData, resStatus) => {
                            wwa_conditional_ui_active = false;
                            const parsed = WWAWebAuthn.parseAjaxResponse(resData);
                            maybeSignalUnknownCredential(parsed);
                            if (resStatus && parsed.success) {
                                wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_6; }, 'class');
                                setTimeout(() => { window.location.href = getLoginSuccessRedirect(parsed); }, 200);
                            } else {
                                wwa_dom('wp-webauthn-notice', (dom) => {
                                    dom.innerHTML = wwa_login_php_vars.terminology === 'passkey'
                                        ? `<span class="wwa-passkey-notice">${wwa_passkey_notice_svg} ${wwa_login_php_vars.i18n_2}</span>`
                                        : `<span><span class="dashicons dashicons-shield-alt"></span> ${wwa_login_php_vars.i18n_2}</span>`;
                                }, 'class');
                                wwa_dom('user_login', (dom) => { dom.readOnly = false; }, 'id');
                                wwa_dom('#wp-webauthn-check, #wp-webauthn', (dom) => { dom.disabled = false; });
                                // Restart Conditional UI after a failed attempt
                                wwa_start_conditional_ui();
                            }
                        }
                    );
                }).catch((err) => {
                    wwa_conditional_ui_active = false;
                    // AbortError is expected when check() aborts — do nothing
                    if (err && err.name !== 'AbortError') {
                        console.warn('WP-WebAuthn Conditional UI error:', err);
                    }
                });
            }
        );
    }).catch(() => { });
}

document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('p#nav') && wwa_login_php_vars.password_reset !== 'false') {
        const placeholder = document.getElementById('wwa-lost-password-link-placeholder');
        if (placeholder) {
            const previous = placeholder.previousSibling;
            const next = placeholder.nextElementSibling;
            if (previous && previous.nodeType === Node.TEXT_NODE && previous.data.trim() === wwa_login_php_vars.separator.trim()) {
                previous.remove();
            } else if (next && next.nodeType === Node.TEXT_NODE && next.data.trim() === wwa_login_php_vars.separator.trim() && !next.nextElementSibling) {
                next.remove();
            }
            placeholder.remove();
        }
    }
    if (document.querySelectorAll('#lostpasswordform, #registerform, .admin-email-confirm-form, #resetpassform').length > 0) {
        return;
    }
    if (document.getElementById('loginform') === null || document.getElementById('loginform').getAttribute('name') !== 'loginform') {
        return;
    }
    document.addEventListener('keydown', parseKey, false);
    let button_check = document.createElement('button');
    button_check.id = 'wp-webauthn-check';
    button_check.type = 'button';
    button_check.className = 'button button-large button-primary';
    button_check.innerHTML = wwa_login_php_vars.i18n_1;
    let button_toggle = document.createElement('button');
    if (wwa_login_php_vars.webauthn_only !== 'true') {
        button_toggle.id = 'wp-webauthn';
        button_toggle.type = 'button';
        button_toggle.className = 'button button-large';
        button_toggle.innerHTML = '<span class="dashicons dashicons-ellipsis password-icon"></span>';
        button_toggle.title = wwa_login_php_vars.i18n_13;
    }
    let submit = document.getElementById('wp-submit');
    if (submit) {
        if (wwa_login_php_vars.webauthn_only !== 'true') {
            submit.parentNode.insertBefore(button_toggle, submit.nextElementSibling);
        }
        submit.parentNode.insertBefore(button_check, submit.nextElementSibling);
    }
    let notice = document.createElement('div');
    notice.className = 'wp-webauthn-notice';
    notice.innerHTML = wwa_login_php_vars.terminology ==='passkey' ? `<span class="wwa-passkey-notice">${wwa_passkey_notice_svg} ${wwa_login_php_vars.i18n_2}</span>` : `<span><span class="dashicons dashicons-shield-alt"></span> ${wwa_login_php_vars.i18n_2}</span>`;
    let forgetmenot = document.getElementsByClassName('forgetmenot');
    if (forgetmenot.length > 0) {
        forgetmenot[0].parentNode.insertBefore(notice, forgetmenot[0]);
    }
    wwa_dom('wp-webauthn-notice', (dom) => {
        const passwordInput = document.getElementsByClassName('user-pass-wrap');
        if (passwordInput.length > 0) {
            dom.style.height = (passwordInput[0].offsetHeight - 10) + 'px';
        } else {
            // WordPress 5.2-
            const legacyPasswordInput = document.getElementById('loginform').getElementsByTagName('p')[1];
            dom.style.height = (legacyPasswordInput.offsetHeight - 10) + 'px';
        }
    }, 'class');
    let btnWidth = document.getElementById('wp-submit') ? document.getElementById('wp-submit').clientWidth : 0;
    if (btnWidth < 20 || btnWidth === undefined) {
        wwa_dom('wp-webauthn-check', (dom) => { dom.style.width = 'auto' }, 'id');
    } else {
        wwa_dom('wp-webauthn-check', (dom) => { dom.style.width = btnWidth }, 'id');
    }
    if (window.PublicKeyCredential === undefined || navigator.credentials.create === undefined || typeof navigator.credentials.create !== 'function') {
        wwaSupported = false;
        wwa_dom('wp-webauthn', (dom) => { dom.style.display = 'none' }, 'id');
    }
    wwa_dom('wp-webauthn-check', (dom) => { dom.addEventListener('click', check, false) }, 'id');
    wwa_dom('wp-webauthn', (dom) => { dom.addEventListener('click', toggle, false) }, 'id');
})

window.onresize = function () {
    if (document.querySelectorAll('#lostpasswordform, #registerform, .admin-email-confirm-form, #resetpassform').length > 0) {
        return;
    }
    let btnWidth = document.getElementById('wp-submit').clientWidth;
    if (btnWidth < 20 || btnWidth === undefined) {
        wwa_dom('wp-webauthn-check', (dom) => { dom.style.width = 'auto' }, 'id');
    } else {
        wwa_dom('wp-webauthn-check', (dom) => { dom.style.width = btnWidth }, 'id');
    }
}

function parseKey(event) {
    if (event.keyCode === 13) {
        if (wwaSupported && document.getElementById('wp-webauthn-check').style.display === 'block') {
            event.preventDefault();
            wwa_dom('wp-webauthn-check', (dom) => { dom.click() }, 'id');
        }
    }
}

function getQueryString(name) {
    let reg = new RegExp(`(^|&)${name}=([^&]*)(&|$)`, 'i');
    let reg_rewrite = new RegExp(`(^|/)${name}/([^/]*)(/|$)`, 'i');
    let r = window.location.search.substr(1).match(reg);
    let q = window.location.pathname.substr(1).match(reg_rewrite);
    if (r != null) {
        return decodeURIComponent(r[2]);
    } else if (q != null) {
        return decodeURIComponent(q[2]);
    } else {
        return null;
    }
}

function getLoginRedirectIntent() {
    const redirectInput = document.querySelector('p.submit input[name="redirect_to"]');
    return redirectInput ? redirectInput.value : (getQueryString('redirect_to') || '');
}

function getLoginSuccessRedirect(parsed) {
    return parsed.redirect || parsed.redirect_to || wwa_login_php_vars.admin_url;
}

function maybeSignalUnknownCredential(parsed) {
    if (parsed.signal && parsed.signal.type === 'unknownCredential') {
        WWAWebAuthn.signalUnknownCredential(parsed.signal.payload);
    }
}

function toggle() {
    if (document.querySelectorAll('#lostpasswordform, #registerform, .admin-email-confirm-form, #resetpassform').length > 0) {
        return;
    }
    if (document.getElementById('loginform') === null || document.getElementById('loginform').getAttribute('name') !== 'loginform') {
        return;
    }
    if (wwaSupported) {
        if (document.getElementsByClassName('wp-webauthn-notice')[0].style.display === 'flex') {
            if (document.getElementsByClassName('user-pass-wrap').length > 0) {
                wwa_dom('.user-pass-wrap, .forgetmenot, #wp-submit', (dom) => { dom.style.display = 'block' });
            } else {
                // WordPress 5.2-
                wwa_dom('.forgetmenot, #wp-submit', (dom) => { dom.style.display = 'block' });
                document.getElementById('loginform').getElementsByTagName('p')[1].style.display = 'block';
            }
            wwa_dom('wp-webauthn-notice', (dom) => { dom.style.display = 'none' }, 'class');
            wwa_dom('wp-webauthn-check', (dom) => { dom.style.cssText = `${dom.style.cssText.split('display: block !important')[0]}display: none !important` }, 'id');
            wwa_dom('user_pass', (dom) => { dom.disabled = false }, 'id');
            wwa_dom('user_login', (dom) => {
                dom.setAttribute('autocomplete', 'username');
                setTimeout(() => {
                    dom.focus();
                }, 0);
            }, 'id');
            wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.terminology ==='passkey' ? `<span class="wwa-passkey-notice">${wwa_passkey_notice_svg} ${wwa_login_php_vars.i18n_2}</span>` : `<span><span class="dashicons dashicons-shield-alt"></span> ${wwa_login_php_vars.i18n_2}</span>` }, 'class');
            wwa_dom('wp-submit', (dom) => { dom.disabled = false }, 'id');
            wwa_dom('wp-webauthn', wwa_login_php_vars.terminology ==='passkey' ? (dom) => {
                dom.innerHTML = wwa_passkey_btn_svg;
                dom.title = wwa_login_php_vars.i18n_14;
                dom.style.lineHeight = '0';
            } : (dom) => {
                dom.innerHTML = '<span class="dashicons dashicons-shield-alt"></span>';
                dom.title = wwa_login_php_vars.i18n_14;
            }, 'id');
            let inputDom = document.querySelectorAll('#loginform label')
            if (inputDom.length > 0) {
                if (document.getElementById('wwa-username-label')) {
                    // WordPress 5.2-
                    document.getElementById('wwa-username-label').innerText = wwa_login_php_vars.i18n_10;
                } else {
                    inputDom[0].innerText = wwa_login_php_vars.i18n_10;
                }
            }
        } else {
            if (document.getElementsByClassName('user-pass-wrap').length > 0) {
                wwa_dom('.user-pass-wrap, #wp-submit', (dom) => { dom.style.display = 'none' });
                if (wwa_login_php_vars.remember_me === 'false' ) {
                    wwa_dom('.forgetmenot', (dom) => { dom.style.display = 'none' });
                }
            } else {
                // WordPress 5.2-
                wwa_dom('#wp-submit', (dom) => { dom.style.display = 'none' });
                if (wwa_login_php_vars.remember_me === 'false' ) {
                    wwa_dom('.forgetmenot', (dom) => { dom.style.display = 'none' });
                }
                document.getElementById('loginform').getElementsByTagName('p')[1].style.display = 'none';
            }
            wwa_dom('wp-webauthn-notice', (dom) => { dom.style.display = 'flex' }, 'class');
            wwa_dom('wp-webauthn-check', (dom) => { dom.style.cssText = `${dom.style.cssText.split('display: none !important')[0]}display: block !important` }, 'id');
            wwa_dom('user_login', (dom) => {
                dom.setAttribute('autocomplete', 'username webauthn');
                setTimeout(() => {
                    dom.focus();
                }, 0);
            }, 'id');
            wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.terminology ==='passkey' ? `<span class="wwa-passkey-notice">${wwa_passkey_notice_svg} ${wwa_login_php_vars.i18n_2}</span>` : `<span><span class="dashicons dashicons-shield-alt"></span> ${wwa_login_php_vars.i18n_2}</span>` }, 'class');
            wwa_dom('wp-submit', (dom) => { dom.disabled = true }, 'id');
            wwa_dom('wp-webauthn', (dom) => {
                dom.innerHTML = '<span class="dashicons dashicons-ellipsis password-icon"></span>';
                dom.title = wwa_login_php_vars.i18n_13;
                dom.style.lineHeight = '';
            }, 'id');
            let inputDom = document.querySelectorAll('#loginform label')
            if (inputDom.length > 0) {
                if (document.getElementById('wwa-username-label')) {
                    // WordPress 5.2-
                    document.getElementById('wwa-username-label').innerText = wwa_login_php_vars.email_login === 'true' ? wwa_login_php_vars.i18n_10 : wwa_login_php_vars.i18n_9;
                } else {
                    inputDom[0].innerText = wwa_login_php_vars.email_login === 'true' ? wwa_login_php_vars.i18n_10 : wwa_login_php_vars.i18n_9;
                }
            }
            // Start Conditional UI when switching into WebAuthn mode
            wwa_start_conditional_ui();
        }
    }
}

// Shake the login form, code from WordPress
function wwa_shake(id, a, d) {
    const c = a.shift();
    document.getElementById(id).style.left = c + 'px';
    if (a.length > 0) {
        setTimeout(() => {
            wwa_shake(id, a, d);
        }, d);
    } else {
        try {
            document.getElementById(id).style.position = 'static';
            wwa_dom('user_login', (dom) => { dom.focus() }, 'id');
        } catch (e) { }
    }
}

function check() {
    if (document.querySelectorAll('#lostpasswordform, #registerform, .admin-email-confirm-form, #resetpassform').length > 0) {
        return;
    }
    if (wwaSupported) {
        if (document.getElementById('user_login').value === '' && wwa_login_php_vars.usernameless !== 'true') {
            wwa_dom('login_error', (dom) => { dom.remove() }, 'id');
            wwa_dom('p.message', (dom) => { dom.remove() });
            if (document.querySelectorAll('#login > h1').length > 0) {
                let dom = document.createElement('div');
                dom.id = 'login_error';
                dom.innerHTML = wwa_login_php_vars.i18n_11;
                document.querySelectorAll('#login > h1')[0].parentNode.insertBefore(dom, document.querySelectorAll('#login > h1')[0].nextElementSibling)
            }
            // Shake the login form, code from WordPress
            let shake = new Array(15, 30, 15, 0, -15, -30, -15, 0);
            shake = shake.concat(shake.concat(shake));
            var form = document.forms[0].id;
            document.getElementById(form).style.position = 'relative';
            wwa_shake(form, shake, 20);
            return;
        }
        // Abort any pending Conditional UI before starting a new modal request
        if (wwa_conditional_ui_abort) {
            wwa_conditional_ui_abort.abort();
            wwa_conditional_ui_abort = null;
            wwa_conditional_ui_active = false;
        }
        wwa_dom('user_login', (dom) => { dom.readOnly = true }, 'id');
        wwa_dom('#wp-webauthn-check, #wp-webauthn', (dom) => { dom.disabled = true });
        wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_3 }, 'class');
        let request = wwa_ajax();
        request.get(wwa_login_php_vars.ajax_url, `?action=wwa_auth_start&user=${encodeURIComponent(document.getElementById('user_login').value)}&type=auth`, (rawData, status) => {
            if (status) {
                wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_4 }, 'class');
                let data = rawData;
                try {
                    data = JSON.parse(rawData);
                } catch (e) {
                    console.warn(rawData);
                    if (wwa_login_php_vars.usernameless === 'true' && document.getElementById('user_login').value === '') {
                        wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_7 + wwa_login_php_vars.i18n_12 }, 'class');
                    } else {
                        wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_7 }, 'class');
                    }
                    wwa_dom('user_login', (dom) => { dom.readOnly = false }, 'id');
                    wwa_dom('#wp-webauthn-check, #wp-webauthn', (dom) => { dom.disabled = false });
                    return;
                }
                const clientID = data.clientID;
                data.allowCredentials = WWAWebAuthn.applyAuthenticatorTypeTransports(data.allowCredentials, wwa_login_php_vars.allow_authenticator_type);
                const publicKey = WWAWebAuthn.parseRequestOptions(data);

                navigator.credentials.get({ 'publicKey': publicKey }).then((credentialInfo) => {
                    wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_5 }, 'class');
                    return credentialInfo;
                }).then(WWAWebAuthn.credentialToJSON).then(JSON.stringify).then((AuthenticatorResponse) => {
                    let response = wwa_ajax();
                    response.post(`${wwa_login_php_vars.ajax_url}?action=wwa_auth`, `data=${encodeURIComponent(window.btoa(AuthenticatorResponse))}&type=auth&clientid=${clientID}&user=${encodeURIComponent(document.getElementById('user_login').value)}&remember=${wwa_login_php_vars.remember_me === 'false' ? 'false' : (document.getElementById('rememberme') ? (document.getElementById('rememberme').checked ? 'true' : 'false') : 'false')}&redirect_to=${encodeURIComponent(getLoginRedirectIntent())}`, (data, status) => {
                        const parsed = WWAWebAuthn.parseAjaxResponse(data);
                        maybeSignalUnknownCredential(parsed);
                        if (status) {
                            if (parsed.success) {
                                wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_6 }, 'class');
                                setTimeout(() => {
                                    window.location.href = getLoginSuccessRedirect(parsed);
                                }, 200);
                            } else {
                                if (wwa_login_php_vars.usernameless === 'true' && document.getElementById('user_login').value === '') {
                                    wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_7 + wwa_login_php_vars.i18n_12 }, 'class');
                                } else {
                                    wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_7 }, 'class');
                                }
                                wwa_dom('user_login', (dom) => { dom.readOnly = false }, 'id');
                                wwa_dom('#wp-webauthn-check, #wp-webauthn', (dom) => { dom.disabled = false });
                            }
                        } else {
                            if (wwa_login_php_vars.usernameless === 'true' && document.getElementById('user_login').value === '') {
                                wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_7 + wwa_login_php_vars.i18n_12 }, 'class');
                            } else {
                                wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_7 }, 'class');
                            }
                            wwa_dom('user_login', (dom) => { dom.readOnly = false }, 'id');
                            wwa_dom('#wp-webauthn-check, #wp-webauthn', (dom) => { dom.disabled = false });
                        }
                    })
                }).catch((error) => {
                    console.warn(error);
                    if (wwa_login_php_vars.usernameless === 'true' && document.getElementById('user_login').value === '') {
                        wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_7 + wwa_login_php_vars.i18n_12 }, 'class');
                    } else {
                        wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_7 }, 'class');
                    }
                    wwa_dom('user_login', (dom) => { dom.readOnly = false }, 'id');
                    wwa_dom('#wp-webauthn-check, #wp-webauthn', (dom) => { dom.disabled = false });
                })
            } else {
                if (wwa_login_php_vars.usernameless === 'true' && document.getElementById('user_login').value === '') {
                    wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_7 + wwa_login_php_vars.i18n_12 }, 'class');
                } else {
                    wwa_dom('wp-webauthn-notice', (dom) => { dom.innerHTML = wwa_login_php_vars.i18n_7 }, 'class');
                }
                wwa_dom('user_login', (dom) => { dom.readOnly = false }, 'id');
                wwa_dom('#wp-webauthn-check, #wp-webauthn', (dom) => { dom.disabled = false });
            }
        })
    }
}
