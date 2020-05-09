// Whether the broswer supports WebAuthn
if (window.PublicKeyCredential === undefined || navigator.credentials.create === undefined || typeof navigator.credentials.create !== "function") {
    jQuery("#bind, #test").attr('disabled', 'disabled');
    jQuery('#show-progress').html(php_vars.i18n_5);
}

jQuery(function(){
    updateList();
})

// Update authenticator list
function updateList(){
    jQuery.ajax({
        url: php_vars.ajax_url,
        type: 'GET',
        data: {
            action: 'wwa_authenticator_list'
        },
        success: function(data){
            if(data.length === 0){
                jQuery("#authenticator-list").html('<tr><td colspan="4">'+php_vars.i18n_17+'</td></tr>');
                return;
            }
            let htmlStr = "";
            for(item of data){
                htmlStr += '<tr><td>'+item.name+'</td><td>'+(item.type === "none" ? php_vars.i18n_9 : (item.type === "platform" ? php_vars.i18n_10 : php_vars.i18n_11))+'</td><td>'+item.added+'</td><td id="'+item.key+'"><a href="javascript:renameAuthenticator(\''+item.key+'\', \''+item.name+'\')">'+php_vars.i18n_20+'</a> | <a href="javascript:removeAuthenticator(\''+item.key+'\', \''+item.name+'\')">'+php_vars.i18n_12+'</a></td></tr>';
            }
            jQuery("#authenticator-list").html(htmlStr);
        },
        error: function(){
            jQuery("#authenticator-list").html('<tr><td colspan="4">'+php_vars.i18n_8+'</td></tr>');
        }
    })
}

/** Code Base64URL into Base64
 * 
 * @param {string} input Base64URL coded string
 */
function base64url2base64(input) {
    input = input.replace(/=/g, "").replace(/-/g, '+').replace(/_/g, '/');
    const pad = input.length % 4;
    if(pad) {
        if(pad === 1) {
            throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
        }
        input += new Array(5-pad).join('=');
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

// Bind an authenticator
jQuery("#bind").click(function(){
    if(jQuery("#authenticator_name").val() === ""){
        alert(php_vars.i18n_7);
        return;
    }

    // Disable inputs to avoid changing in process
    jQuery('#show-progress').html(php_vars.i18n_1);
    jQuery("#bind").attr('disabled', 'disabled');
    jQuery("#authenticator_name").attr('readonly', 'readonly');
    if(jQuery("#authenticator_type").val() === "none"){
        jQuery("#type-platform").attr('disabled', 'disabled');
        jQuery("#type-cross-platform").attr('disabled', 'disabled');
    }else if(jQuery("#authenticator_type").val() === "platform"){
        jQuery("#type-none").attr('disabled', 'disabled');
        jQuery("#type-cross-platform").attr('disabled', 'disabled');
    }else if(jQuery("#authenticator_type").val() === "cross-platform"){
        jQuery("#type-none").attr('disabled', 'disabled');
        jQuery("#type-platform").attr('disabled', 'disabled');
    }
    jQuery.ajax({
        url: php_vars.ajax_url,
        type: 'GET',
        data: {
            action: 'wwa_create',
            name: jQuery("#authenticator_name").val(),
            type: jQuery("#authenticator_type").val(),
        },
        success: function(data){
            // Get the args, code string into Uint8Array
            jQuery('#show-progress').text(php_vars.i18n_2);
            let challenge = new Uint8Array(32);
            let user_id = new Uint8Array(32);
            challenge = Uint8Array.from(window.atob(base64url2base64(data.challenge)), c=>c.charCodeAt(0));
            user_id = Uint8Array.from(window.atob(base64url2base64(data.user.id)), c=>c.charCodeAt(0));

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
            if(data.excludeCredentials){
                public_key.excludeCredentials = data.excludeCredentials.map(function(item){
                    item.id = Uint8Array.from(window.atob(base64url2base64(item.id)), function(c){return c.charCodeAt(0);});
                    return item;
                })
            }

            // Create, a pop-up window should appear
            navigator.credentials.create({ 'publicKey': public_key }).then((newCredentialInfo) => {
                jQuery('#show-progress').html(php_vars.i18n_6);
                return newCredentialInfo;
            }).then(function(data){
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
            }).then(JSON.stringify).then(function(AuthenticatorAttestationResponse) {
                // Send attestation back to RP
                jQuery.ajax({
                    url: php_vars.ajax_url+"?action=wwa_create_response",
                    type: 'POST',
                    data: {
                        data: window.btoa(AuthenticatorAttestationResponse),
                        name: jQuery("#authenticator_name").val(),
                        type: jQuery("#authenticator_type").val()
                    },
                    success: function(data){
                        if(data === "true"){
                            // Registered
                            jQuery('#show-progress').html(php_vars.i18n_3);
                            jQuery("#bind").removeAttr('disabled');
                            jQuery("#authenticator_name").val("");
                            jQuery("#authenticator_name").removeAttr('readonly');
                            jQuery(".sub-type").removeAttr('disabled');
                            updateList();
                        }else{
                            // Register failed
                            jQuery('#show-progress').html(php_vars.i18n_4);
                            jQuery("#bind").removeAttr('disabled');
                            jQuery("#authenticator_name").removeAttr('readonly');
                            jQuery(".sub-type").removeAttr('disabled');
                            updateList();
                        }
                    },
                    error: function(){
                        jQuery('#show-progress').html(php_vars.i18n_4);
                        jQuery("#bind").removeAttr('disabled');
                        jQuery("#authenticator_name").removeAttr('readonly');
                        jQuery(".sub-type").removeAttr('disabled');
                        updateList();
                    }
                })
            }).catch((error) => {
                // Creation abort
                console.warn(error);
                jQuery('#show-progress').html(php_vars.i18n_4+": "+error);
                jQuery("#bind").removeAttr('disabled');
                jQuery("#authenticator_name").removeAttr('readonly');
                jQuery(".sub-type").removeAttr('disabled');
                updateList();
            })
        },
        error: function(){
            jQuery('#show-progress').html(php_vars.i18n_4);
            jQuery("#bind").removeAttr('disabled');
            jQuery("#authenticator_name").removeAttr('readonly');
            jQuery(".sub-type").removeAttr('disabled');
            updateList();
        }
    })
});

// Test WebAuthn
jQuery("#test").click(function(){
    jQuery('#show-test').text(php_vars.i18n_1);
    jQuery("#test").attr("disabled", "disabled");
    jQuery.ajax({
        url: php_vars.ajax_url,
        type: 'GET',
        data: {
            action: 'wwa_auth_start',
            type: 'test'
        },
        success: function(data){
            if(data === "User not inited."){
                jQuery('#show-test').html(php_vars.i18n_15+": "+php_vars.i18n_17);
                jQuery("#test").removeAttr('disabled');
                return;
            }
            jQuery('#show-test').text(php_vars.i18n_13);
            data.challenge = Uint8Array.from(window.atob(base64url2base64(data.challenge)), c=>c.charCodeAt(0));

            if (data.allowCredentials) {
                data.allowCredentials = data.allowCredentials.map(function(item) {
                    item.id = Uint8Array.from(window.atob(base64url2base64(item.id)), function(c){return c.charCodeAt(0);});
                    return item;
                });
            }

            navigator.credentials.get({ 'publicKey': data }).then((credentialInfo) => {
                jQuery('#show-test').html(php_vars.i18n_14);
                return credentialInfo;
            }).then(function(data) {
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
            }).then(JSON.stringify).then(function(AuthenticatorResponse) {
                jQuery.ajax({
                    url: php_vars.ajax_url+"?action=wwa_auth",
                    type: 'POST',
                    data: {
                        data: window.btoa(AuthenticatorResponse),
                        type: 'test'
                    },
                    success: function(data){
                        if(data === "true"){
                            jQuery('#show-test').html(php_vars.i18n_16);
                            jQuery("#test").removeAttr('disabled');
                        }else{
                            jQuery('#show-test').html(php_vars.i18n_15);
                            jQuery("#test").removeAttr('disabled');
                        }
                    },
                    error: function(){
                        jQuery('#show-test').html(php_vars.i18n_15);
                        jQuery("#test").removeAttr('disabled');
                    }
                })
            }).catch((error) => {
                console.warn(error);
                jQuery('#show-test').html(php_vars.i18n_15+": "+error);
                jQuery("#test").removeAttr('disabled');
            })
        },
        error: function(){
            jQuery('#show-test').html(php_vars.i18n_15);
            jQuery("#test").removeAttr('disabled');
        }
    })
});

/**
 * Rename an authenticator
 * @param {string} id Authenticator ID
 * @param {string} name Current authenticator name
 */
function renameAuthenticator(id, name){
    let new_name = prompt(php_vars.i18n_21, name);
    if(new_name === ""){
        alert(php_vars.i18n_7);
    }else if(new_name !== null && new_name !== name){
        jQuery("#"+id).text(php_vars.i18n_22)
        jQuery.ajax({
            url: php_vars.ajax_url,
            type: 'GET',
            data: {
                action: 'wwa_modify_authenticator',
                id: id,
                name: new_name,
                target: 'rename'
            },
            success: function(){
                updateList();
            },
            error: function(data){
                alert("Error: "+data);
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
function removeAuthenticator(id, name){
    if(confirm(php_vars.i18n_18+name)){
        jQuery("#"+id).text(php_vars.i18n_19)
        jQuery.ajax({
            url: php_vars.ajax_url,
            type: 'GET',
            data: {
                action: 'wwa_modify_authenticator',
                id: id,
                target: 'remove'
            },
            success: function(){
                updateList();
            },
            error: function(data){
                alert("Error: "+data);
                updateList();
            }
        })
    }
}