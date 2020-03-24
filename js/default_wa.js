jQuery(function(){
    if(!(window.PublicKeyCredential === undefined || typeof window.PublicKeyCredential !== "function" || navigator.credentials.create === undefined || typeof navigator.credentials.create !== "function")){
        // If supported, toggle
        jQuery('.user-pass-wrap,.forgetmenot,#wp-submit').hide();
        jQuery('#wp-webauthn-check, .wp-webauthn-notice').show();
        jQuery("#user_login").focus();
        jQuery("#wp-submit").attr("disabled", "disabled");
    }
    window.onload = function(){
        jQuery("#user_pass").removeAttr("disabled");
        jQuery("#loginform label").first().text(php_vars.i18n_9);
    }
})