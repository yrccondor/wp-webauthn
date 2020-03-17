$(function(){
	if (!(window.PublicKeyCredential === undefined || typeof window.PublicKeyCredential !== "function" || navigator.credentials.create === undefined || typeof navigator.credentials.create !== "function")){
        // If supported, toggle
        $('.user-pass-wrap,.forgetmenot,#wp-submit').hide();
        $('#wp-webauthn-check, .wp-webauthn-notice').show();
        $("#user_login").focus();
    }
    window.onload = function(){
        $("#user_pass").removeAttr("disabled");
        $("#wp-submit").attr("disabled", "disabled");
        $("#loginform label").first().text(php_vars.i18n_9);
    }
})