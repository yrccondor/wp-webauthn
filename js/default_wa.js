document.addEventListener('DOMContentLoaded',function(){
    if(document.querySelectorAll("#lostpasswordform, #registerform").length > 0){
        return;
    }
    if(!(window.PublicKeyCredential === undefined || navigator.credentials.create === undefined || typeof navigator.credentials.create !== "function")){
        // If supported, toggle
        wwa_dom(".user-pass-wrap,.forgetmenot,#wp-submit", (dom)=>{dom.style.display = "none"});
        wwa_dom("wp-webauthn-notice", (dom)=>{dom.style.display = "block"}, "class");
        wwa_dom("wp-webauthn-check", (dom)=>{dom.style.cssText = dom.style.cssText + "display: block !important"}, "id");
        wwa_dom("user_login", (dom)=>{dom.focus()}, "id");
        wwa_dom("wp-submit", (dom)=>{dom.disabled = true}, "id");
    }
    window.onload = function(){
        if(document.querySelectorAll("#lostpasswordform, #registerform").length > 0){
            return;
        }
        wwa_dom("user_pass", (dom)=>{dom.disabled = false}, "id");
        let dom = document.querySelectorAll("#loginform label");
        if(dom.length > 0){
            dom[0].innerText =php_vars.i18n_9;
        }
    }
})