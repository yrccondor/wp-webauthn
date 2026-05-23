const svg = `<svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" style="enable-background:new 0 0 216 216" viewBox="0 0 216 216" class="wwa-table-svg"><style>.st2{fill-rule:evenodd;clip-rule:evenodd;fill:#818286}</style><g id="Isolation_Mode"><path d="M0 0h216v216H0z" style="fill:none"/><path d="M172.32 96.79c0 13.78-8.48 25.5-20.29 29.78l7.14 11.83-10.57 13 10.57 12.71-17.04 22.87-12.01-12.82V125.7c-10.68-4.85-18.15-15.97-18.15-28.91 0-17.4 13.51-31.51 30.18-31.51 16.66 0 30.17 14.11 30.17 31.51zm-30.18 4.82c4.02 0 7.28-3.4 7.28-7.6 0-4.2-3.26-7.61-7.28-7.61s-7.28 3.4-7.28 7.61c-.01 4.2 3.26 7.6 7.28 7.6z" style="fill-rule:evenodd;clip-rule:evenodd;fill:#a2a1a3"/><path d="M172.41 96.88c0 13.62-8.25 25.23-19.83 29.67l6.58 11.84-9.73 13 9.73 12.71-17.03 23.05v-85.54c4.02 0 7.28-3.41 7.28-7.6 0-4.2-3.26-7.61-7.28-7.61V65.28c16.73 0 30.28 14.15 30.28 31.6zM120.24 131.43c-9.75-8-16.3-20.3-17.2-34.27H50.8c-10.96 0-19.84 9.01-19.84 20.13v25.17c0 5.56 4.44 10.07 9.92 10.07h69.44c5.48 0 9.92-4.51 9.92-10.07v-11.03z" class="st2"/><path d="M73.16 91.13c-2.42-.46-4.82-.89-7.11-1.86-8.65-3.63-13.69-10.32-15.32-19.77-1.12-6.47-.59-12.87 2.03-18.92 3.72-8.6 10.39-13.26 19.15-14.84 5.24-.94 10.46-.73 15.5 1.15 7.59 2.82 12.68 8.26 15.03 16.24 2.38 8.05 2.03 16.1-1.56 23.72-3.72 7.96-10.21 12.23-18.42 13.9-.68.14-1.37.27-2.05.41-2.41-.03-4.83-.03-7.25-.03z" style="fill:#818286"/></g></svg>`;

// Whether the broswer supports WebAuthn
if (window.PublicKeyCredential === undefined || navigator.credentials.create === undefined || typeof navigator.credentials.create !== 'function') {
    jQuery('#wwa-bind, #wwa-test').attr('disabled', 'disabled');
    jQuery('#wwa-show-progress').html(php_vars.i18n_5);
}

jQuery(() => {
    updateList();
})

function maybeSignalCurrentUserDetails() {
    if (String(php_vars.user_id) !== String(php_vars.current_user_id)) {
        return;
    }
    WWAWebAuthn.signalCurrentUserDetailsFromEndpoint(php_vars.ajax_url, php_vars._ajax_nonce);
}

window.addEventListener('load', () => {
    if (document.getElementById('wp-webauthn-error-container')) {
        document.getElementById('wp-webauthn-error-container').insertBefore(document.getElementById('wp-webauthn-error'), null);
    }
    if (document.getElementById('wp-webauthn-message-container')) {
        document.getElementById('wp-webauthn-message-container').insertBefore(document.getElementById('wp-webauthn-message'), null);
    }
})

function getErrorMessage(error) {
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

// Update authenticator list
function setAuthenticatorListMessage(message) {
    const list = document.getElementById('wwa-authenticator-list');
    if (!list) {
        return;
    }
    list.textContent = '';
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = getColspan();
    cell.textContent = message;
    row.appendChild(cell);
    list.appendChild(row);
}

function appendAuthenticatorIcon(cell) {
    const template = document.createElement('template');
    template.innerHTML = svg.trim();
    cell.appendChild(template.content.firstChild);
}

function createAuthenticatorAction(label, handler) {
    const link = document.createElement('a');
    link.href = '#';
    link.textContent = label;
    link.addEventListener('click', (event) => {
        event.preventDefault();
        handler();
    });
    return link;
}

function getAuthenticatorTypeLabel(item, item_type_disabled) {
    const typeLabel = item.type === 'none' ? php_vars.i18n_9 : (item.type === 'platform' ? php_vars.i18n_10 : php_vars.i18n_11);
    return item_type_disabled ? typeLabel + php_vars.i18n_29 : typeLabel;
}

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
                setAuthenticatorListMessage(php_vars.i18n_8);
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
                setAuthenticatorListMessage(php_vars.i18n_17);
                jQuery('#wwa_usernameless_tip').text('');
                jQuery('#wwa_usernameless_tip').hide();
                jQuery('#wwa_type_tip').text('');
                jQuery('#wwa_type_tip').hide();
                maybeSignalCurrentUserDetails();
                return;
            }
            const list = document.getElementById('wwa-authenticator-list');
            list.textContent = '';
            let has_usernameless = false;
            let has_disabled_type = false;
            for (const item of data) {
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
                const row = document.createElement('tr');

                const nameCell = document.createElement('td');
                appendAuthenticatorIcon(nameCell);
                nameCell.appendChild(document.createTextNode(item.name));
                row.appendChild(nameCell);

                if (configs.show_authenticator_type === 'true') {
                    const typeCell = document.createElement('td');
                    typeCell.className = 'wwa-type-td';
                    typeCell.textContent = getAuthenticatorTypeLabel(item, item_type_disabled);
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
                usernamelessCell.textContent = item.usernameless ? php_vars.i18n_24 + (configs.usernameless === 'true' ? '' : php_vars.i18n_26) : php_vars.i18n_25;
                row.appendChild(usernamelessCell);

                const actionCell = document.createElement('td');
                actionCell.id = item.key;
                actionCell.appendChild(createAuthenticatorAction(php_vars.i18n_20, () => renameAuthenticator(item.key, item.name)));
                actionCell.appendChild(document.createTextNode(' | '));
                actionCell.appendChild(createAuthenticatorAction(php_vars.i18n_12, () => removeAuthenticator(item.key, item.name)));
                row.appendChild(actionCell);

                list.appendChild(row);
            }
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
            maybeSignalCurrentUserDetails();
        },
        error: function () {
            setAuthenticatorListMessage(php_vars.i18n_8);
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
    WWAWebAuthn.abortConditionalCreate();

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
                jQuery('#wwa-show-progress').text(`${php_vars.i18n_4_text}: ${data}`);
                jQuery('#wwa-bind').removeAttr('disabled');
                jQuery('#wwa_authenticator_name').removeAttr('disabled');
                jQuery('.wwa_authenticator_usernameless').removeAttr('disabled');
                if (configs.show_authenticator_type === 'true') {
                    jQuery('#wwa_authenticator_type').removeAttr('disabled');
                }
                updateList();
                return;
            }
            jQuery('#wwa-show-progress').text(php_vars.i18n_2);
            const clientID = data.clientID;
            const public_key = WWAWebAuthn.parseCreationOptions(data);

            navigator.credentials.create({ 'publicKey': public_key }).then((newCredentialInfo) => {
                jQuery('#wwa-show-progress').html(php_vars.i18n_6);
                return newCredentialInfo;
            }).then(WWAWebAuthn.credentialToJSON).then(JSON.stringify).then((AuthenticatorAttestationResponse) => {
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
                        const parsed = WWAWebAuthn.parseAjaxResponse(data);
                        if (parsed.success) {
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
                            maybeSignalCurrentUserDetails();
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
                jQuery('#wwa-show-progress').text(`${php_vars.i18n_4_text}: ${getErrorMessage(error)}`);
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
    WWAWebAuthn.abortConditionalCreate();
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
                jQuery(tip_id).text(`${php_vars.i18n_15_text}: ${data}`);
                jQuery('#wwa-test, #wwa-test_usernameless').removeAttr('disabled');
                return;
            }
            if (data === 'User not inited.') {
                jQuery(tip_id).text(`${php_vars.i18n_15_text}: ${php_vars.i18n_17}`);
                jQuery('#wwa-test, #wwa-test_usernameless').removeAttr('disabled');
                return;
            }
            jQuery(tip_id).text(php_vars.i18n_13);
            const clientID = data.clientID;
            data.allowCredentials = WWAWebAuthn.applyAuthenticatorTypeTransports(data.allowCredentials, configs.allow_authenticator_type);
            const publicKey = WWAWebAuthn.parseRequestOptions(data);

            navigator.credentials.get({ 'publicKey': publicKey }).then((credentialInfo) => {
                jQuery(tip_id).html(php_vars.i18n_14);
                return credentialInfo;
            }).then(WWAWebAuthn.credentialToJSON).then(JSON.stringify).then((AuthenticatorResponse) => {
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
                        const parsed = WWAWebAuthn.parseAjaxResponse(data);
                        if (parsed.signal && parsed.signal.type === 'unknownCredential') {
                            WWAWebAuthn.signalUnknownCredential(parsed.signal.payload);
                        }
                        if (parsed.success) {
                            jQuery(tip_id).html(php_vars.i18n_16);
                            jQuery('#wwa-test, #wwa-test_usernameless').removeAttr('disabled');
                            updateList();
                        } else {
                            jQuery(tip_id).html(php_vars.i18n_15);
                            jQuery('#wwa-test, #wwa-test_usernameless').removeAttr('disabled');
                        }
                    },
                    error: function (xhr) {
                        const parsed = WWAWebAuthn.parseAjaxResponse(xhr && xhr.responseText ? xhr.responseText : '');
                        if (parsed.signal && parsed.signal.type === 'unknownCredential') {
                            WWAWebAuthn.signalUnknownCredential(parsed.signal.payload);
                        }
                        jQuery(tip_id).html(php_vars.i18n_15);
                        jQuery('#wwa-test, #wwa-test_usernameless').removeAttr('disabled');
                    }
                })
            }).catch((error) => {
                console.warn(error);
                jQuery(tip_id).text(`${php_vars.i18n_15_text}: ${getErrorMessage(error)}`);
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
                alert(`Error: ${getErrorMessage(data)}`);
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
                alert(`Error: ${getErrorMessage(data)}`);
                updateList();
            }
        })
    }
}
