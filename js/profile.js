const svg = `<svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" style="enable-background:new 0 0 216 216" viewBox="0 0 216 216" class="wwa-table-svg"><style>.st2{fill-rule:evenodd;clip-rule:evenodd;fill:#818286}</style><g id="Isolation_Mode"><path d="M0 0h216v216H0z" style="fill:none"/><path d="M172.32 96.79c0 13.78-8.48 25.5-20.29 29.78l7.14 11.83-10.57 13 10.57 12.71-17.04 22.87-12.01-12.82V125.7c-10.68-4.85-18.15-15.97-18.15-28.91 0-17.4 13.51-31.51 30.18-31.51 16.66 0 30.17 14.11 30.17 31.51zm-30.18 4.82c4.02 0 7.28-3.4 7.28-7.6 0-4.2-3.26-7.61-7.28-7.61s-7.28 3.4-7.28 7.61c-.01 4.2 3.26 7.6 7.28 7.6z" style="fill-rule:evenodd;clip-rule:evenodd;fill:#a2a1a3"/><path d="M172.41 96.88c0 13.62-8.25 25.23-19.83 29.67l6.58 11.84-9.73 13 9.73 12.71-17.03 23.05v-85.54c4.02 0 7.28-3.41 7.28-7.6 0-4.2-3.26-7.61-7.28-7.61V65.28c16.73 0 30.28 14.15 30.28 31.6zM120.24 131.43c-9.75-8-16.3-20.3-17.2-34.27H50.8c-10.96 0-19.84 9.01-19.84 20.13v25.17c0 5.56 4.44 10.07 9.92 10.07h69.44c5.48 0 9.92-4.51 9.92-10.07v-11.03z" class="st2"/><path d="M73.16 91.13c-2.42-.46-4.82-.89-7.11-1.86-8.65-3.63-13.69-10.32-15.32-19.77-1.12-6.47-.59-12.87 2.03-18.92 3.72-8.6 10.39-13.26 19.15-14.84 5.24-.94 10.46-.73 15.5 1.15 7.59 2.82 12.68 8.26 15.03 16.24 2.38 8.05 2.03 16.1-1.56 23.72-3.72 7.96-10.21 12.23-18.42 13.9-.68.14-1.37.27-2.05.41-2.41-.03-4.83-.03-7.25-.03z" style="fill:#818286"/></g></svg>`;

// Whether the broswer supports WebAuthn
if (window.PublicKeyCredential === undefined || navigator.credentials.create === undefined || typeof navigator.credentials.create !== 'function') {
    jQuery('#wwa-bind, #wwa-test').attr('disabled', 'disabled');
    jQuery('#wwa-show-progress').html(php_vars.i18n_5);
}

jQuery(() => {
    updateList();
})

window.addEventListener('load', () => {
    if (document.getElementById('wp-webauthn-error-container')) {
        document.getElementById('wp-webauthn-error-container').insertBefore(document.getElementById('wp-webauthn-error'), null);
    }
    if (document.getElementById('wp-webauthn-message-container')) {
        document.getElementById('wp-webauthn-message-container').insertBefore(document.getElementById('wp-webauthn-message'), null);
    }
})

// Update authenticator list
function updateList() {
    jQuery.ajax({
        url: php_vars.ajax_url,
        type: 'GET',
        data: {
            action: 'wwa_authenticator_list',
            user_id: php_vars.user_id,
            _ajax_nonce: php_vars._ajax_nonce
        },
        success: function (data) {
            if (typeof data === 'string') {
                console.warn(data);
                jQuery('#wwa-authenticator-list').html(`<tr><td colspan="${getColspan()}">${php_vars.i18n_8}</td></tr>`);
                return;
            }
            if (data.length === 0) {
                if (configs.usernameless === 'true') {
                    jQuery('.wwa-usernameless-th, .wwa-usernameless-td').show();
                } else {
                    jQuery('.wwa-usernameless-th, .wwa-usernameless-td').hide();
                }
                if (configs.show_authenticator_type === 'true') {
                    jQuery('.wwa-type-th, .wwa-type-td').show();
                } else {
                    jQuery('.wwa-type-th, .wwa-type-td').hide();
                }
                jQuery('#wwa-authenticator-list').html(`<tr><td colspan="${getColspan()}">${php_vars.i18n_17}</td></tr>`);
                jQuery('#wwa_usernameless_tip').text('');
                jQuery('#wwa_usernameless_tip').hide();
                jQuery('#wwa_type_tip').text('');
                jQuery('#wwa_type_tip').hide();
                return;
            }
            let htmlStr = '';
            let has_usernameless = false;
            let has_disabled_type = false;
            for (item of data) {
                let item_type_disabled = false;
                if (item.usernameless) {
                    has_usernameless = true;
                }
                if (configs.allow_authenticator_type !== 'none') {
                    if (configs.allow_authenticator_type !== item.type) {
                        has_disabled_type = true;
                        item_type_disabled = true;
                    }
                }
                htmlStr += `<tr><td>${svg}${item.name}</td>${configs.show_authenticator_type === 'true' ? `<td class="wwa-type-td">${item.type === 'none' ? php_vars.i18n_9 : (item.type === 'platform' ? php_vars.i18n_10 : php_vars.i18n_11)}${item_type_disabled ? php_vars.i18n_29 : ''}</td>` : ''}<td>${item.added}</td><td>${item.last_used}</td><td class="wwa-usernameless-td">${item.usernameless ? php_vars.i18n_24 + (configs.usernameless === 'true' ? '' : php_vars.i18n_26) : php_vars.i18n_25}</td><td id="${item.key}"><a href="javascript:renameAuthenticator('${item.key}', '${item.name.replaceAll('\'', '\\\'').replaceAll('&#039;', '\\&#039;').replaceAll('"', '\\"')}')">${php_vars.i18n_20}</a> | <a href="javascript:removeAuthenticator('${item.key}', '${item.name.replaceAll('\'', '\\\'').replaceAll('&#039;', '\\&#039;').replaceAll('"', '\\"')}')">${php_vars.i18n_12}</a></td></tr>`;
            }
            jQuery('#wwa-authenticator-list').html(htmlStr);
            if (has_usernameless || configs.usernameless === 'true') {
                jQuery('.wwa-usernameless-th, .wwa-usernameless-td').show();
            } else {
                jQuery('.wwa-usernameless-th, .wwa-usernameless-td').hide();
            }
            if (configs.show_authenticator_type === 'true') {
                jQuery('.wwa-type-th, .wwa-type-td').show();
            } else {
                jQuery('.wwa-type-th, .wwa-type-td').hide();
            }
            if (has_usernameless && configs.usernameless !== 'true') {
                jQuery('#wwa_usernameless_tip').text(php_vars.i18n_27);
                jQuery('#wwa_usernameless_tip').show();
            } else {
                jQuery('#wwa_usernameless_tip').text('');
                jQuery('#wwa_usernameless_tip').hide();
            }
            if (has_disabled_type && configs.allow_authenticator_type !== 'none') {
                if (configs.allow_authenticator_type === 'platform') {
                    jQuery('#wwa_type_tip').text(php_vars.i18n_30);
                } else {
                    jQuery('#wwa_type_tip').text(php_vars.i18n_31);
                }
                jQuery('#wwa_type_tip').show();
            } else {
                jQuery('#wwa_type_tip').text('');
                jQuery('#wwa_type_tip').hide();
            }
        },
        error: function () {
            jQuery('#wwa-authenticator-list').html(`<tr><td colspan="${getColspan()}">${php_vars.i18n_8}</td></tr>`);
        }
    })
}

// Compute current number of visible columns for colspan
function getColspan() {
    let cols = 4; // Identifier, Registered, Last used, Action
    if (jQuery('.wwa-type-th').length > 0 && jQuery('.wwa-type-th').css('display') !== 'none') {
        cols++;
    }
    if (jQuery('.wwa-usernameless-th').length > 0 && jQuery('.wwa-usernameless-th').css('display') !== 'none') {
        cols++;
    }
    return cols;
}

/** Code Base64URL into Base64
 *
 * @param {string} input Base64URL coded string
 */
function base64url2base64(input) {
    input = input.replace(/=/g, '').replace(/-/g, '+').replace(/_/g, '/');
    const pad = input.length % 4;
    if (pad) {
        if (pad === 1) {
            throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
        }
        input += new Array(5 - pad).join('=');
    }
    return input;
}

/** Code Uint8Array into Base64 string
 *
 * @param {Uint8Array} a The Uint8Array needed to be coded into Base64 string
 */
function arrayToBase64String(a) {
    return btoa(String.fromCharCode(...a));
}

jQuery('#wwa-add-new-btn').click((e) => {
    e.preventDefault();
    jQuery('#wwa-new-block').show();
    jQuery('#wwa-verify-block').hide();
    setTimeout(() => {
        jQuery('#wwa-new-block').focus();
    }, 0);
})

jQuery('#wwa-verify-btn').click((e) => {
    e.preventDefault();
    jQuery('#wwa-new-block').hide();
    jQuery('#wwa-verify-block').show();
    setTimeout(() => {
        jQuery('#wwa-verify-block').focus();
    }, 0);
})

jQuery('.wwa-cancel').click((e) => {
    e.preventDefault();
    jQuery('#wwa-new-block').hide();
    jQuery('#wwa-verify-block').hide();
})

// Prevent WebAuthn registration fields from triggering WordPress's unsaved changes dialog.
// The form="wwa-registration" attribute on these inputs disassociates them from #your-profile,
// so they are excluded from jQuery serialize() comparisons in user-profile.js.

jQuery('#wwa_authenticator_name').keydown((e) => {
    if (e.keyCode === 13) {
        jQuery('#wwa-bind').trigger('click');
        e.preventDefault();
    }
  });

// Bind an authenticator
jQuery('#wwa-bind').click((e) => {
    e.preventDefault();
    if (jQuery('#wwa_authenticator_name').val() === '') {
        alert(php_vars.i18n_7);
        return;
    }

    // Disable inputs to avoid changing in process
    jQuery('#wwa-show-progress').html(php_vars.i18n_1);
    jQuery('#wwa-bind').attr('disabled', 'disabled');
    jQuery('#wwa_authenticator_name').attr('disabled', 'disabled');
    jQuery('.wwa_authenticator_usernameless').attr('disabled', 'disabled');
    if (configs.show_authenticator_type === 'true') {
        jQuery('#wwa_authenticator_type').attr('disabled', 'disabled');
    }
    jQuery.ajax({
        url: php_vars.ajax_url,
        type: 'GET',
        data: {
            action: 'wwa_create',
            name: jQuery('#wwa_authenticator_name').val(),
            type: configs.show_authenticator_type === 'true' ? jQuery('#wwa_authenticator_type').val() : (configs.allow_authenticator_type !== 'none' ? configs.allow_authenticator_type : 'none'),
            usernameless: jQuery('.wwa_authenticator_usernameless:checked').val() ? jQuery('.wwa_authenticator_usernameless:checked').val() : 'false',
            user_id: php_vars.user_id,
            _ajax_nonce: php_vars._ajax_nonce
        },
        success: function (data) {
            if (typeof data === 'string') {
                console.warn(data);
                jQuery('#wwa-show-progress').html(`${php_vars.i18n_4}: ${data}`);
                jQuery('#wwa-bind').removeAttr('disabled');
                jQuery('#wwa_authenticator_name').removeAttr('disabled');
                jQuery('.wwa_authenticator_usernameless').removeAttr('disabled');
                if (configs.show_authenticator_type === 'true') {
                    jQuery('#wwa_authenticator_type').removeAttr('disabled');
                }
                updateList();
                return;
            }
            // Get the args, code string into Uint8Array
            jQuery('#wwa-show-progress').text(php_vars.i18n_2);
            let challenge = new Uint8Array(32);
            let user_id = new Uint8Array(32);
            challenge = Uint8Array.from(window.atob(base64url2base64(data.challenge)), (c) => c.charCodeAt(0));
            user_id = Uint8Array.from(window.atob(base64url2base64(data.user.id)), (c) => c.charCodeAt(0));

            let public_key = {
                challenge: challenge,
                rp: {
                    id: data.rp.id,
                    name: data.rp.name
                },
                user: {
                    id: user_id,
                    name: data.user.name,
                    displayName: data.user.displayName
                },
                pubKeyCredParams: data.pubKeyCredParams,
                authenticatorSelection: data.authenticatorSelection,
                timeout: data.timeout
            }

            // If some authenticators are already registered, exclude
            if (data.excludeCredentials) {
                public_key.excludeCredentials = data.excludeCredentials.map((item) => {
                    item.id = Uint8Array.from(window.atob(base64url2base64(item.id)), (c) => c.charCodeAt(0));
                    return item;
                })
            }

            // Save client ID
            const clientID = data.clientID;
            delete data.clientID;

            // Create, a pop-up window should appear
            navigator.credentials.create({ 'publicKey': public_key }).then((newCredentialInfo) => {
                jQuery('#wwa-show-progress').html(php_vars.i18n_6);
                return newCredentialInfo;
            }).then((data) => {
                // Code Uint8Array into string for transmission
                const publicKeyCredential = {
                    id: data.id,
                    type: data.type,
                    rawId: arrayToBase64String(new Uint8Array(data.rawId)),
                    response: {
                        clientDataJSON: arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
                        attestationObject: arrayToBase64String(new Uint8Array(data.response.attestationObject))
                    }
                };
                return publicKeyCredential;
            }).then(JSON.stringify).then((AuthenticatorAttestationResponse) => {
                // Send attestation back to RP
                jQuery.ajax({
                    url: `${php_vars.ajax_url}?action=wwa_create_response`,
                    type: 'POST',
                    data: {
                        data: window.btoa(AuthenticatorAttestationResponse),
                        name: jQuery('#wwa_authenticator_name').val(),
                        type: configs.show_authenticator_type === 'true' ? jQuery('#wwa_authenticator_type').val() : (configs.allow_authenticator_type !== 'none' ? configs.allow_authenticator_type : 'none'),
                        usernameless: jQuery('.wwa_authenticator_usernameless:checked').val() ? jQuery('.wwa_authenticator_usernameless:checked').val() : 'false',
                        clientid: clientID,
                        user_id: php_vars.user_id,
                        _ajax_nonce: php_vars._ajax_nonce
                    },
                    success: function (data) {
                        if (data.trim() === 'true') {
                            // Registered
                            jQuery('#wwa-show-progress').html(php_vars.i18n_3);
                            jQuery('#wwa-bind').removeAttr('disabled');
                            jQuery('#wwa_authenticator_name').removeAttr('disabled');
                            jQuery('#wwa_authenticator_name').val('');
                            jQuery('.wwa_authenticator_usernameless').removeAttr('disabled');
                            if (configs.show_authenticator_type === 'true') {
                                jQuery('#wwa_authenticator_type').removeAttr('disabled');
                            }
                            updateList();
                        } else {
                            // Register failed
                            jQuery('#wwa-show-progress').html(php_vars.i18n_4);
                            jQuery('#wwa-bind').removeAttr('disabled');
                            jQuery('#wwa_authenticator_name').removeAttr('disabled');
                            jQuery('.wwa_authenticator_usernameless').removeAttr('disabled');
                            if (configs.show_authenticator_type === 'true') {
                                jQuery('#wwa_authenticator_type').removeAttr('disabled');
                            }
                            updateList();
                        }
                    },
                    error: function () {
                        jQuery('#wwa-show-progress').html(php_vars.i18n_4);
                        jQuery('#wwa-bind').removeAttr('disabled');
                        jQuery('#wwa_authenticator_name').removeAttr('disabled');
                        jQuery('.wwa_authenticator_usernameless').removeAttr('disabled');
                        if (configs.show_authenticator_type === 'true') {
                            jQuery('#wwa_authenticator_type').removeAttr('disabled');
                        }
                        updateList();
                    }
                })
            }).catch((error) => {
                // Creation abort
                console.warn(error);
                jQuery('#wwa-show-progress').html(`${php_vars.i18n_4}: ${error}`);
                jQuery('#wwa-bind').removeAttr('disabled');
                jQuery('#wwa_authenticator_name').removeAttr('disabled');
                jQuery('.wwa_authenticator_usernameless').removeAttr('disabled');
                if (configs.show_authenticator_type === 'true') {
                    jQuery('#wwa_authenticator_type').removeAttr('disabled');
                }
                updateList();
            })
        },
        error: function () {
            jQuery('#wwa-show-progress').html(php_vars.i18n_4);
            jQuery('#wwa-bind').removeAttr('disabled');
            jQuery('#wwa_authenticator_name').removeAttr('disabled');
            jQuery('.wwa_authenticator_usernameless').removeAttr('disabled');
            if (configs.show_authenticator_type === 'true') {
                jQuery('#wwa_authenticator_type').removeAttr('disabled');
            }
            updateList();
        }
    })
});

// Test WebAuthn
jQuery('#wwa-test, #wwa-test_usernameless').click((e) => {
    e.preventDefault();
    jQuery('#wwa-test, #wwa-test_usernameless').attr('disabled', 'disabled');
    let button_id = e.target.id;
    let usernameless = 'false';
    let tip_id = '#wwa-show-test';
    if (button_id === 'wwa-test_usernameless') {
        usernameless = 'true';
        tip_id = '#wwa-show-test-usernameless';
    }
    jQuery(tip_id).text(php_vars.i18n_1);
    jQuery.ajax({
        url: php_vars.ajax_url,
        type: 'GET',
        data: {
            action: 'wwa_auth_start',
            type: 'test',
            usernameless: usernameless,
            user_id: php_vars.user_id
        },
        success: function (data) {
            if (typeof data === 'string') {
                console.warn(data);
                jQuery(tip_id).html(`${php_vars.i18n_15}: ${data}`);
                jQuery('#wwa-test, #wwa-test_usernameless').removeAttr('disabled');
                return;
            }
            if (data === 'User not inited.') {
                jQuery(tip_id).html(`${php_vars.i18n_15}: ${php_vars.i18n_17}`);
                jQuery('#wwa-test, #wwa-test_usernameless').removeAttr('disabled');
                return;
            }
            jQuery(tip_id).text(php_vars.i18n_13);
            data.challenge = Uint8Array.from(window.atob(base64url2base64(data.challenge)), (c) => c.charCodeAt(0));

            if (data.allowCredentials) {
                data.allowCredentials = data.allowCredentials.map((item) => {
                    item.id = Uint8Array.from(window.atob(base64url2base64(item.id)), (c) => c.charCodeAt(0));
                    return item;
                });
            }

            if (data.allowCredentials && configs.allow_authenticator_type && configs.allow_authenticator_type !== 'none') {
                for (let credential of data.allowCredentials) {
                    if (configs.allow_authenticator_type === 'cross-platform') {
                        credential.transports = ['usb', 'nfc', 'ble'];
                    } else if (configs.allow_authenticator_type === 'platform') {
                        credential.transports = ['internal'];
                    }
                }
            }

            // Save client ID
            const clientID = data.clientID;
            delete data.clientID;

            navigator.credentials.get({ 'publicKey': data }).then((credentialInfo) => {
                jQuery(tip_id).html(php_vars.i18n_14);
                return credentialInfo;
            }).then((data) => {
                const publicKeyCredential = {
                    id: data.id,
                    type: data.type,
                    rawId: arrayToBase64String(new Uint8Array(data.rawId)),
                    response: {
                        authenticatorData: arrayToBase64String(new Uint8Array(data.response.authenticatorData)),
                        clientDataJSON: arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
                        signature: arrayToBase64String(new Uint8Array(data.response.signature)),
                        userHandle: data.response.userHandle ? arrayToBase64String(new Uint8Array(data.response.userHandle)) : null
                    }
                };
                return publicKeyCredential;
            }).then(JSON.stringify).then((AuthenticatorResponse) => {
                jQuery.ajax({
                    url: `${php_vars.ajax_url}?action=wwa_auth`,
                    type: 'POST',
                    data: {
                        data: window.btoa(AuthenticatorResponse),
                        type: 'test',
                        remember: 'false',
                        clientid: clientID,
                        user_id: php_vars.user_id
                    },
                    success: function (data) {
                        if (data.trim() === 'true') {
                            jQuery(tip_id).html(php_vars.i18n_16);
                            jQuery('#wwa-test, #wwa-test_usernameless').removeAttr('disabled');
                            updateList();
                        } else {
                            jQuery(tip_id).html(php_vars.i18n_15);
                            jQuery('#wwa-test, #wwa-test_usernameless').removeAttr('disabled');
                        }
                    },
                    error: function () {
                        jQuery(tip_id).html(php_vars.i18n_15);
                        jQuery('#wwa-test, #wwa-test_usernameless').removeAttr('disabled');
                    }
                })
            }).catch((error) => {
                console.warn(error);
                jQuery(tip_id).html(`${php_vars.i18n_15}: ${error}`);
                jQuery('#wwa-test, #wwa-test_usernameless').removeAttr('disabled');
            })
        },
        error: function () {
            jQuery(tip_id).html(php_vars.i18n_15);
            jQuery('#wwa-test, #wwa-test_usernameless').removeAttr('disabled');
        }
    })
});

/**
 * Rename an authenticator
 * @param {string} id Authenticator ID
 * @param {string} name Current authenticator name
 */
function renameAuthenticator(id, name) {
    let new_name = prompt(php_vars.i18n_21, name);
    if (new_name === '') {
        alert(php_vars.i18n_7);
    } else if (new_name !== null && new_name !== name) {
        jQuery(`#${id}`).text(php_vars.i18n_22)
        jQuery.ajax({
            url: php_vars.ajax_url,
            type: 'GET',
            data: {
                action: 'wwa_modify_authenticator',
                id: id,
                name: new_name,
                target: 'rename',
                user_id: php_vars.user_id,
                _ajax_nonce: php_vars._ajax_nonce
            },
            success: function () {
                updateList();
            },
            error: function (data) {
                alert(`Error: ${data}`);
                updateList();
            }
        })
    }
}

/**
 * Remove an authenticator
 * @param {string} id Authenticator ID
 * @param {string} name Authenticator name
 */
function removeAuthenticator(id, name) {
    if (confirm(php_vars.i18n_18 + name + (jQuery('#wwa-authenticator-list > tr').length === 1 ? '\n' + php_vars.i18n_28 : ''))) {
        jQuery(`#${id}`).text(php_vars.i18n_19)
        jQuery.ajax({
            url: php_vars.ajax_url,
            type: 'GET',
            data: {
                action: 'wwa_modify_authenticator',
                id: id,
                target: 'remove',
                user_id: php_vars.user_id,
                _ajax_nonce: php_vars._ajax_nonce
            },
            success: function () {
                updateList();
            },
            error: function (data) {
                alert(`Error: ${data}`);
                updateList();
            }
        })
    }
}
