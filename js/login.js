let wwaSupported = true;
jQuery(function(){
    jQuery('#wp-submit').after('<button id="wp-webauthn-check" type="button" class="button button-large button-primary">'+php_vars.i18n_1+'</button><button id="wp-webauthn" type="button" class="button button-large"><span class="dashicons dashicons-update-alt"></span></button>');
    jQuery('.forgetmenot').before('<div class="wp-webauthn-notice"><span class="dashicons dashicons-shield-alt"></span> '+php_vars.i18n_2+'</div>');
    jQuery('.wp-webauthn-notice').css({'height': (jQuery('.user-pass-wrap').height() - 10) + 'px', 'line-height': (jQuery('.user-pass-wrap').height() - 10) + 'px'});
    jQuery("#wp-webauthn-check").width(jQuery("#wp-submit").width());
    if (window.PublicKeyCredential === undefined || typeof window.PublicKeyCredential !== "function" || navigator.credentials.create === undefined || typeof navigator.credentials.create !== "function") {
        wwaSupported = false;
        jQuery("#wp-webauthn").hide();
    }
    jQuery('#wp-webauthn-check').click(check);
    jQuery('#wp-webauthn').click(toggle);
})

window.onresize = function(){
    jQuery("#wp-webauthn-check").width(jQuery("#wp-submit").width());
}

document.addEventListener("keydown", parseKey, false);

function parseKey(event) {
    if(wwaSupported && jQuery('#wp-webauthn-check').css('display') === 'block'){
        if(event.keyCode === 13){
            event.preventDefault();
            jQuery('#wp-webauthn-check').click();
        }
    }
}

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


function arrayToBase64String(a) {
    return btoa(String.fromCharCode(...a));
}

function getQueryString(name) {
    var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)", "i");
    var reg_rewrite = new RegExp("(^|/)" + name + "/([^/]*)(/|$)", "i");
    var r = window.location.search.substr(1).match(reg);
    var q = window.location.pathname.substr(1).match(reg_rewrite);
    if(r != null){
        return unescape(r[2]);
    }else if(q != null){
        return unescape(q[2]);
    }else{
        return null;
    }
}

function toggle(){
    if(wwaSupported){
        if(jQuery('#wp-webauthn-check').css('display') === 'block'){
            jQuery('.user-pass-wrap,.forgetmenot,#wp-submit').show();
            jQuery('#wp-webauthn-check, .wp-webauthn-notice').hide();
            jQuery("#user_pass").removeAttr("disabled");
            jQuery("#user_login").focus();
            jQuery('.wp-webauthn-notice').html('<span class="dashicons dashicons-shield-alt"></span> '+php_vars.i18n_2);
            jQuery("#wp-submit").removeAttr("disabled");
            jQuery("#loginform label").first().text(php_vars.i18n_10);
        }else{
            jQuery('.user-pass-wrap,.forgetmenot,#wp-submit').hide();
            jQuery('#wp-webauthn-check, .wp-webauthn-notice').show();
            jQuery("#user_login").focus();
            jQuery('.wp-webauthn-notice').html('<span class="dashicons dashicons-shield-alt"></span> '+php_vars.i18n_2);
            jQuery("#wp-submit").attr("disabled", "disabled");
            jQuery("#loginform label").first().text(php_vars.i18n_9);
        }
    }
}

// Shake the login form, code from WordPress
function wwa_shake(id, a, d) {
    c = a.shift();
    document.getElementById(id).style.left = c + 'px';
    if (a.length > 0) {
        setTimeout(function() {
            wwa_shake(id, a, d);
        }, d);
    } else {
        try {
            document.getElementById(id).style.position = 'static';
            jQuery("#user_login").focus();
        } catch (e) {}
    }
}

function check(){
    if(wwaSupported){
        if(jQuery("#user_login").val() === ""){
            jQuery("#login_error").remove();
            jQuery("p.message").remove();
            jQuery("#login > h1").first().after('<div id="login_error"> '+php_vars.i18n_11+'</div>');
            // Shake the login form, code from WordPress
            let shake = new Array(15,30,15,0,-15,-30,-15,0);
            shake = shake.concat(shake.concat(shake));
            var form = document.forms[0].id;
            document.getElementById(form).style.position = 'relative';
            wwa_shake(form, shake, 20);
            return;
        }
        jQuery("#user_login").attr("readonly", "readonly");
        jQuery("#wp-webauthn-check, #wp-webauthn").attr("disabled", "disabled");
        jQuery('.wp-webauthn-notice').html(php_vars.i18n_3);
        jQuery.ajax({
            url: php_vars.ajax_url,
            type: 'GET',
            data: {
                action: 'wwa_auth_start',
                type: 'auth',
                user: jQuery("#user_login").val()
            },
            success: function(data){
                jQuery('.wp-webauthn-notice').html(php_vars.i18n_4)
                data.challenge = Uint8Array.from(window.atob(base64url2base64(data.challenge)), c=>c.charCodeAt(0));
    
                if (data.allowCredentials) {
                    data.allowCredentials = data.allowCredentials.map(function(item) {
                        item.id = Uint8Array.from(window.atob(base64url2base64(item.id)), function(c){return c.charCodeAt(0);});
                        return item;
                    });
                }
    
                navigator.credentials.get({ 'publicKey': data }).then((credentialInfo) => {
                    jQuery('.wp-webauthn-notice').html(php_vars.i18n_5)
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
                            type: 'auth',
                            user: jQuery("#user_login").val()
                        },
                        success: function(data){
                            if(data === "true"){
                                jQuery('.wp-webauthn-notice').html(php_vars.i18n_6);
                                if(getQueryString("redirect_to")){
                                    setTimeout(()=>{
                                        window.location.href = getQueryString("redirect_to");
                                    }, 200);
                                }else{
                                    setTimeout(()=>{
                                        window.location.href = php_vars.admin_url
                                    }, 200);
                                }
                            }else{
                                jQuery('.wp-webauthn-notice').html(php_vars.i18n_7);
                                jQuery("#user_login").removeAttr("readonly");
                                jQuery("#wp-webauthn-check, #wp-webauthn").removeAttr("disabled");
                            }
                        },
                        error: function(){
                            jQuery('.wp-webauthn-notice').html(php_vars.i18n_7);
                            jQuery("#user_login").removeAttr("readonly");
                            jQuery("#wp-webauthn-check, #wp-webauthn").removeAttr("disabled");
                        }
                    })
                }).catch((error) => {
                    console.warn(error);
                    jQuery('.wp-webauthn-notice').html(php_vars.i18n_7);
                    jQuery("#user_login").removeAttr("readonly");
                    jQuery("#wp-webauthn-check, #wp-webauthn").removeAttr("disabled");
                })
            },
            error: function(){
                jQuery('.wp-webauthn-notice').html(php_vars.i18n_7);
                jQuery("#user_login").removeAttr("readonly");
                jQuery("#wp-webauthn-check, #wp-webauthn").removeAttr("disabled");
            }
        })
    }
}