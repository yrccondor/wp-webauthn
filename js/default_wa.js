jQuery(function(){
    if(jQuery("#lostpasswordform, #registerform").length){
        return;
    }
    if(!(window.PublicKeyCredential === undefined || navigator.credentials.create === undefined || typeof navigator.credentials.create !== "function")){
        // If supported, toggle
        jQuery('.user-pass-wrap,.forgetmenot,#wp-submit').hide();
        jQuery('.wp-webauthn-notice').show();
        jQuery('#wp-webauthn-check').attr("style", jQuery('#wp-webauthn-check').attr("style")+"display: block !important");
        jQuery("#user_login").focus();
        jQuery("#wp-submit").attr("disabled", "disabled");
    }
    window.onload = function(){
        if(jQuery("#lostpasswordform, #registerform").length){
            return;
        }
        jQuery("#user_pass").removeAttr("disabled");
        jQuery("#loginform label").first().text(php_vars.i18n_9);
    }
})