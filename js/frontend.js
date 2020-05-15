'use strict';

// Send an AJAX request and get the response
let wwa_ajax = function() {
    let xmlHttpReq = new XMLHttpRequest();
    return {
        /** Send an AJAX GET request and get the response
         * 
         * @param {string} url URL
         * @param {string} data Attached data
         * @param {object} callback Callback function
         */
        get: function(url, data = "", callback = ()=>{}){
            xmlHttpReq.open("GET", url+data, true);
            xmlHttpReq.send();
            xmlHttpReq.onreadystatechange = function(){
                if(xmlHttpReq.readyState === 4 && xmlHttpReq.status === 200){
                    callback(xmlHttpReq.responseText, true);
                }else if(xmlHttpReq.readyState === 4){
                    callback("Network Error.", false);
                }
            }
        },
        /** Send an AJAX POST request and get the response
         * 
         * @param {string} url URL
         * @param {string} data Attached data
         * @param {object} callback Callback function
         */
        post: function(url, data = "", callback = ()=>{}){
            xmlHttpReq.open("POST", url, true);
            xmlHttpReq.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
            xmlHttpReq.send(data);
            xmlHttpReq.onreadystatechange = function(){
                if(xmlHttpReq.readyState === 4 && xmlHttpReq.status === 200){
                    callback(xmlHttpReq.responseText, true);
                }else if(xmlHttpReq.readyState === 4){
                    callback("Network Error.", false);
                }
            }
        }
    }
};

/** Operate selected DOMs
 * 
 * @param {string} selector DOM selector
 * @param {object} callback Callbck function
 * @param {string} method Selecte method
 */
let wwa_dom = function(selector, callback = ()=>{}, method = "query"){
    let dom_list = [];
    if(method === "id"){
        let dom = document.getElementById(selector);
        if(dom){
            callback(dom);
        }
        return;
    }else if(method === "class"){
        dom_list = document.getElementsByClassName(selector);
    }else if(method === "tag"){
        dom_list = document.getElementsByTagName(selector);
    }else{
        dom_list = document.querySelectorAll(selector);
    }
    for(let dom of dom_list){
        callback(dom);
    }
    return;
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

// Disable all WP-Webauthn buttons
function wwa_disable_buttons(){
    wwa_dom("wwa-test-submit", (dom)=>{dom.disabled = true}, "class");
    wwa_dom("wwa-test-usernameless-submit", (dom)=>{dom.disabled = true}, "class");
    wwa_dom("wwa-bind-submit", (dom)=>{dom.disabled = true}, "class");
    wwa_dom("wwa-login-submit", (dom)=>{dom.disabled = true}, "class");
    wwa_dom("wp-submit", (dom)=>{dom.disabled = true}, "id");
}

// Enable all WP-Webauthn buttons
function wwa_enable_buttons(){
    wwa_dom("wwa-test-submit", (dom)=>{dom.disabled = false}, "class");
    wwa_dom("wwa-test-usernameless-submit", (dom)=>{dom.disabled = false}, "class");
    wwa_dom("wwa-bind-submit", (dom)=>{dom.disabled = false}, "class");
    wwa_dom("wwa-login-submit", (dom)=>{dom.disabled = false}, "class");
    wwa_dom("wp-submit", (dom)=>{dom.disabled = false}, "id");
}

document.addEventListener('DOMContentLoaded',function(){
    wwa_dom("wwa-login-submit", (dom)=>{dom.addEventListener('click', wwa_auth, false)}, "class");
    // If traditional form exists
    if(document.getElementsByClassName("wwa-login-form-traditional").length > 0){
        wwa_dom(".wwa-login-form-traditional .login-password", (dom)=>{
            let height = dom.clientHeight;
            wwa_dom(".wwa-login-form-webauthn .wp-webauthn-notice", (ele)=>{
                ele.style.height = height - 40.4 + "px";
                ele.style.lineHeight = height - 40.4 + "px";
            });
        });
        wwa_dom("wwa-w2t", (dom)=>{dom.addEventListener('click', wwa_toggle, false)}, "class");
        wwa_dom("wwa-t2w", (dom)=>{dom.addEventListener('click', wwa_toggle, false)}, "class");
    }else{
        wwa_dom(".wwa-login-form-webauthn .wp-webauthn-notice", (ele)=>{
            ele.style.height = "40.6px";
            ele.style.lineHeight = "40.6px";
        });
        wwa_dom("wwa-w2t", (dom)=>{dom.parentNode.removeChild(document.getElementsByClassName("wwa-w2t")[0])}, "class");
    }
    // If not support
    if(window.PublicKeyCredential === undefined || navigator.credentials.create === undefined || typeof navigator.credentials.create !== "function"){
        wwa_dom("wwa-test-submit", (dom)=>{dom.disabled = true}, "class");
        wwa_dom("wwa-test-usernameless-submit", (dom)=>{dom.disabled = true}, "class");
        wwa_dom("wwa-bind-submit", (dom)=>{dom.disabled = true}, "class");
        wwa_dom("wwa-show-test", (dom)=>{dom.innerText = wwa_php_vars.i18n_31}, "class");
        wwa_dom("wwa-show-progress", (dom)=>{dom.innerText = wwa_php_vars.i18n_31}, "class");
        if(document.getElementsByClassName("wwa-login-form-traditional").length > 0){
            wwa_dom("wwa-login-form-webauthn", (dom)=>{dom.classList.add("wwa-hide-form")}, "class");
        }
        return;
    }
    wwa_dom("wwa-login-form-traditional", (dom)=>{dom.classList.add("wwa-hide-form")}, "class");
    wwa_dom("wwa-bind-submit", (dom)=>{dom.addEventListener('click', wwa_bind, false)}, "class");
    wwa_dom("wwa-test-submit", (dom)=>{dom.addEventListener('click', wwa_verify, false)}, "class");
    wwa_dom("wwa-test-usernameless-submit", (dom)=>{dom.addEventListener('click', wwa_verify, false)}, "class");
});

// Toggle form
function wwa_toggle(){
    if(document.getElementsByClassName("wwa-login-form-traditional").length > 0){
        // Disable buttons if it is not shown
        if(document.getElementsByClassName("wwa-login-form-traditional")[0].className.indexOf("wwa-hide-form") !== -1){
            wwa_dom("wp-submit", (dom)=>{dom.disabled = false}, "id");
            wwa_dom("wwa-login-submit", (dom)=>{dom.disabled = true}, "class");
        }else{
            wwa_dom("wp-submit", (dom)=>{dom.disabled = true}, "id");
            wwa_dom("wwa-login-submit", (dom)=>{dom.disabled = false}, "class");
        }
        document.getElementsByClassName("wwa-login-form-traditional")[0].classList.toggle("wwa-hide-form");
        document.getElementsByClassName("wwa-login-form-webauthn")[0].classList.toggle("wwa-hide-form");
    }
}

// Auth
function wwa_auth(){
    if(window.PublicKeyCredential === undefined || navigator.credentials.create === undefined || typeof navigator.credentials.create !== "function"){
        alert(wwa_php_vars.i18n_31);
        return;
    }
    let wwa_username = this.parentNode.previousElementSibling.previousElementSibling.getElementsByClassName("wwa-user-name")[0].value;
    if(wwa_username === "" && wwa_php_vars.usernameless !== "true"){
        alert(wwa_php_vars.i18n_11);
        return;
    }
    wwa_dom("wwa-user-name", (dom)=>{dom.readOnly = true}, "class");
    wwa_disable_buttons();
    let button_dom = this;
    button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_3;
    let request = wwa_ajax();
    request.get(wwa_php_vars.ajax_url, "?action=wwa_auth_start&user="+encodeURIComponent(wwa_username)+"&type=auth", (rawData, status)=>{
        if(status){
            button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_4;
            let data = JSON.parse(rawData);
            data.challenge = Uint8Array.from(window.atob(base64url2base64(data.challenge)), c=>c.charCodeAt(0));
    
            if (data.allowCredentials) {
                data.allowCredentials = data.allowCredentials.map(function(item) {
                    item.id = Uint8Array.from(window.atob(base64url2base64(item.id)), function(c){return c.charCodeAt(0);});
                    return item;
                });
            }
    
            navigator.credentials.get({ 'publicKey': data }).then((credentialInfo) => {
                button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_5;
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
            }).then(JSON.stringify).then(function(AuthenticatorResponse){
                let response = wwa_ajax();
                response.post(wwa_php_vars.ajax_url+"?action=wwa_auth", "data="+encodeURIComponent(window.btoa(AuthenticatorResponse))+"&type=auth&user="+encodeURIComponent(wwa_username), (data, status)=>{
                    if(status){
                        if(data === "true"){
                            wwa_enable_buttons();
                            wwa_dom("wwa-user-name", (dom)=>{dom.readOnly = false}, "class");
                            button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_6;
                            if(document.querySelectorAll('p.login-submit input[name="redirect_to"]').length > 0){
                                setTimeout(()=>{
                                    window.location.href = document.querySelectorAll('p.login-submit input[name="redirect_to"]')[0].value;
                                }, 200);
                            }else{
                                if(document.getElementsByClassName("wwa-redirect-to").length > 0){
                                    setTimeout(()=>{
                                        window.location.href = document.getElementsByClassName("wwa-redirect-to")[0].value;
                                    }, 200);
                                }else{
                                    setTimeout(()=>{
                                        window.location.reload();
                                    }, 200);
                                }
                            }
                        }else{
                            wwa_enable_buttons();
                            if(wwa_php_vars.usernameless === "true" && wwa_username === ""){
                                button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7+wwa_php_vars.i18n_33;
                                wwa_dom("wwa-try-username", (dom)=>{dom.style.transform = 'translateY(-' + (parseInt(button_dom.parentNode.previousElementSibling.style.lineHeight) - 20) + 'px)'}, "class");
                            }else{
                                button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7;
                            }
                            wwa_dom("wwa-user-name", (dom)=>{dom.readOnly = false}, "class");
                        }
                    }else{
                        wwa_enable_buttons();
                        if(wwa_php_vars.usernameless === "true" && wwa_username === ""){
                            button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7+wwa_php_vars.i18n_33;
                            wwa_dom("wwa-try-username", (dom)=>{dom.style.transform = 'translateY(-' + (parseInt(button_dom.parentNode.previousElementSibling.style.lineHeight) - 20) + 'px)'}, "class");
                        }else{
                            button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7;
                        }
                        wwa_dom("wwa-user-name", (dom)=>{dom.readOnly = false}, "class");
                    }
                })
            }).catch((error) => {
                console.warn(error);
                wwa_enable_buttons();
                if(wwa_php_vars.usernameless === "true" && wwa_username === ""){
                    button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7+wwa_php_vars.i18n_33;
                    wwa_dom("wwa-try-username", (dom)=>{dom.style.transform = 'translateY(-' + (parseInt(button_dom.parentNode.previousElementSibling.style.lineHeight) - 20) + 'px)'}, "class");
                }else{
                    button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7;
                }
                wwa_dom("wwa-user-name", (dom)=>{dom.readOnly = false}, "class");
            })
        }else{
            wwa_enable_buttons();
            if(wwa_php_vars.usernameless === "true" && wwa_username === ""){
                button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7+wwa_php_vars.i18n_33;
                wwa_dom("wwa-try-username", (dom)=>{dom.style.transform = 'translateY(-' + (parseInt(button_dom.parentNode.previousElementSibling.style.lineHeight) - 20) + 'px)'}, "class");
            }else{
                button_dom.parentNode.previousElementSibling.innerHTML = wwa_php_vars.i18n_7;
            }
            wwa_dom("wwa-user-name", (dom)=>{dom.readOnly = false}, "class");
        }
    })
}

// Bind
function wwa_bind(){
    let button_dom = this;
    let wwa_name = this.parentNode.parentNode.getElementsByClassName("wwa-authenticator-name")[0].value;
    if(wwa_name === ""){
        alert(wwa_php_vars.i18n_12);
        return;
    }
    let wwa_type = this.parentNode.parentNode.getElementsByClassName("wwa-authenticator-type")[0].value;
    let wwa_usernameless = this.parentNode.parentNode.querySelectorAll(".wwa-authenticator-usernameless:checked")[0].value;
    button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_3;
    wwa_disable_buttons();
    // Lock options
    wwa_dom("wwa-authenticator-name", (dom)=>{dom.readOnly = true}, "class");
    wwa_dom("wwa-authenticator-type", (dom)=>{dom.disabled = true}, "class");
    wwa_dom("wwa-authenticator-usernameless", (dom)=>{dom.disabled = true}, "class");
    let request = wwa_ajax();
    request.get(wwa_php_vars.ajax_url, "?action=wwa_create&name="+encodeURIComponent(wwa_name)+"&type="+encodeURIComponent(wwa_type)+"&usernameless="+wwa_usernameless, (rawData, status)=>{
        if(status){
            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_28;
            let data = JSON.parse(rawData);
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
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_32;
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
                let response = wwa_ajax();
                response.post(wwa_php_vars.ajax_url+"?action=wwa_create_response", "data="+encodeURIComponent(window.btoa(AuthenticatorAttestationResponse))+"&name="+encodeURIComponent(wwa_name)+"&type="+encodeURIComponent(wwa_type), (rawData, status)=>{
                    if(status){
                        if(rawData === "true"){
                            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_29;
                            wwa_enable_buttons();
                            wwa_dom("wwa-authenticator-name", (dom)=>{dom.readOnly = false}, "class");
                            wwa_dom("wwa-authenticator-type", (dom)=>{dom.disabled = false}, "class");
                            wwa_dom("wwa-authenticator-usernameless", (dom)=>{dom.disabled = false}, "class");
                            updateList();
                        }else{
                            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_30;
                            wwa_enable_buttons();
                            wwa_dom("wwa-authenticator-name", (dom)=>{dom.readOnly = false}, "class");
                            wwa_dom("wwa-authenticator-type", (dom)=>{dom.disabled = false}, "class");
                            wwa_dom("wwa-authenticator-usernameless", (dom)=>{dom.disabled = false}, "class");
                            updateList();
                        }
                    }else{
                        button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_30;
                        wwa_enable_buttons();
                        wwa_dom("wwa-authenticator-name", (dom)=>{dom.readOnly = false}, "class");
                        wwa_dom("wwa-authenticator-type", (dom)=>{dom.disabled = false}, "class");
                        wwa_dom("wwa-authenticator-usernameless", (dom)=>{dom.disabled = false}, "class");
                        updateList();
                    }
                })
            }).catch((error) => {
                console.warn(error);
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_30;
                wwa_enable_buttons();
                wwa_dom("wwa-authenticator-name", (dom)=>{dom.readOnly = false}, "class");
                wwa_dom("wwa-authenticator-type", (dom)=>{dom.disabled = false}, "class");
                wwa_dom("wwa-authenticator-usernameless", (dom)=>{dom.disabled = false}, "class");
                updateList();
            })
        }else{
            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_30;
            wwa_enable_buttons();
            wwa_dom("wwa-authenticator-name", (dom)=>{dom.readOnly = false}, "class");
            wwa_dom("wwa-authenticator-type", (dom)=>{dom.disabled = false}, "class");
            wwa_dom("wwa-authenticator-usernameless", (dom)=>{dom.disabled = false}, "class");
            updateList();
        }
    })
}

// Verify
function wwa_verify(){
    let button_dom = this;
    button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_3;
    let usernameless = this.className.indexOf("wwa-test-usernameless-submit") === -1 ? false : true;
    wwa_disable_buttons();
    let request = wwa_ajax();
    request.get(wwa_php_vars.ajax_url, "?action=wwa_auth_start&type=test&usernameless="+(usernameless ? "true" : "false"), (rawData, status)=>{
        if(status){
            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_4;
            if(rawData === "User not inited."){
                wwa_enable_buttons();
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_15;
                return;
            }
            let data = JSON.parse(rawData);
            data.challenge = Uint8Array.from(window.atob(base64url2base64(data.challenge)), c=>c.charCodeAt(0));

            if (data.allowCredentials) {
                data.allowCredentials = data.allowCredentials.map(function(item) {
                    item.id = Uint8Array.from(window.atob(base64url2base64(item.id)), function(c){return c.charCodeAt(0);});
                    return item;
                });
            }

            navigator.credentials.get({ 'publicKey': data }).then((credentialInfo) => {
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_13;
                return credentialInfo;
            }).then(function(data) {
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_14;
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
            }).then(JSON.stringify).then(function(AuthenticatorResponse){
                let response = wwa_ajax();
                response.post(wwa_php_vars.ajax_url+"?action=wwa_auth", "data="+encodeURIComponent(window.btoa(AuthenticatorResponse))+"&type=test", (rawData, status)=>{
                    if(status){
                        if(rawData === "true"){
                            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_16;
                            wwa_enable_buttons();
                        }else{
                            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_15;
                            wwa_enable_buttons();
                        }
                    }else{
                        button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_15;
                        wwa_enable_buttons();
                    }
                })
            }).catch((error) => {
                console.warn(error);
                button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_15;
                wwa_enable_buttons();
            })
        }else{
            button_dom.nextElementSibling.innerHTML = wwa_php_vars.i18n_15;
            wwa_enable_buttons();
        }
    })
}

// Update authenticator list
function updateList(){
    if(document.getElementsByClassName("wwa-authenticator-list").length === 0){
        return;
    }
    let request = wwa_ajax();
    request.get(wwa_php_vars.ajax_url, "?action=wwa_authenticator_list", (rawData, status) => {
        if(status){
            let data = JSON.parse(rawData);
            if(data.length === 0){
                wwa_dom("wwa-authenticator-list", (dom)=>{dom.innerHTML = '<tr><td colspan="6">'+wwa_php_vars.i18n_23+'</td></tr>'}, "class");
                return;
            }
            let htmlStr = "";
            for(let item of data){
                htmlStr += '<tr><td>'+item.name+'</td><td>'+(item.type === "none" ? wwa_php_vars.i18n_24 : (item.type === "platform" ? wwa_php_vars.i18n_25 : wwa_php_vars.i18n_26))+'</td><td>'+item.added+'</td><td>'+(item.usernameless ? wwa_php_vars.i18n_1+(wwa_php_vars.usernameless === "true" ? "" : wwa_php_vars.i18n_9) : wwa_php_vars.i18n_8)+'</td><td class="wwa-key-'+item.key+'"><a href="javascript:renameAuthenticator(\''+item.key+'\', \''+item.name+'\')">'+wwa_php_vars.i18n_20+'</a> | <a href="javascript:removeAuthenticator(\''+item.key+'\', \''+item.name+'\')">'+wwa_php_vars.i18n_27+'</a></td></tr>';
            }
            wwa_dom("wwa-authenticator-list", (dom)=>{dom.innerHTML = htmlStr}, "class");
            if(wwa_php_vars.usernameless !== "true"){
                wwa_dom("wwa-authenticator-list-usernameless-tip", (dom)=>{dom.innerText = wwa_php_vars.i18n_10;dom.style.display = "block"}, "class");
            }else{
                wwa_dom("wwa-authenticator-list-usernameless-tip", (dom)=>{dom.innerText = "";dom.style.display = "none"}, "class");
            }
        }else{
            wwa_dom("wwa-authenticator-list", (dom)=>{dom.innerHTML = '<tr><td colspan="6">'+wwa_php_vars.i18n_17+'</td></tr>'}, "class");
        }
    })
}

/** Rename an authenticator
 * 
 * @param {string} id Authenticator ID
 * @param {string} name Current authenticator name
 */
function renameAuthenticator(id, name){
    let new_name = prompt(wwa_php_vars.i18n_21, name);
    if(new_name === ""){
        alert(wwa_php_vars.i18n_12);
    }else if(new_name !== null && new_name !== name){
        let request = wwa_ajax();
        wwa_dom("wwa-key-"+id, (dom)=>{dom.innerText = wwa_php_vars.i18n_22}, "class");
        request.get(wwa_php_vars.ajax_url, "?action=wwa_modify_authenticator&id="+encodeURIComponent(id)+"&name="+encodeURIComponent(new_name)+"&target=rename", (data, status) => {
            if(status){
                updateList();
            }else{
                alert("Error: "+data);
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
function removeAuthenticator(id, name){
    if(confirm(wwa_php_vars.i18n_18+name)){
        wwa_dom("wwa-key-"+id, (dom)=>{dom.innerText = wwa_php_vars.i18n_19}, "class");
        let request = wwa_ajax();
        request.get(wwa_php_vars.ajax_url, "?action=wwa_modify_authenticator&id="+encodeURIComponent(id)+"&target=remove", (data, status) => {
            if(status){
                updateList();
            }else{
                alert("Error: "+data);
                updateList();
            }
        })
    }
}