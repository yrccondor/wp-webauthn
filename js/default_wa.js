document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelectorAll('#lostpasswordform,#registerform').length > 0) {
        return;
    }
    window.onload = () => {
        if (!(window.PublicKeyCredential === undefined || navigator.credentials.create === undefined || typeof navigator.credentials.create !== 'function')) {
            // If supported, toggle
            if (document.getElementsByClassName('user-pass-wrap') > 0) {
                wwa_dom('.user-pass-wrap,.forgetmenot,#wp-submit', (dom) => { dom.style.display = 'none' });
            } else {
                // WordPress 5.2-
                wwa_dom('.forgetmenot,#wp-submit', (dom) => { dom.style.display = 'none' });
                document.getElementById('loginform').getElementsByTagName('p')[1].style.display = 'none';
            }
            wwa_dom('wp-webauthn-notice', (dom) => { dom.style.display = 'block' }, 'class');
            wwa_dom('wp-webauthn-check', (dom) => { dom.style.cssText = `${dom.style.cssText}display: block !important` }, 'id');
            wwa_dom('user_login', (dom) => { dom.focus() }, 'id');
            wwa_dom('wp-submit', (dom) => { dom.disabled = true }, 'id');
        }
        if (document.querySelectorAll('#lostpasswordform,#registerform').length > 0) {
            return;
        }
        wwa_dom('user_pass', (dom) => { dom.disabled = false }, 'id');
        let dom = document.querySelectorAll('#loginform label');
        if (dom.length > 0) {
            if (dom[0].getElementsByTagName('input').length > 0) {
                // WordPress 5.2-
                dom[0].innerHTML = `<span id="wwa-username-label">${php_vars.i18n_9}</span>${dom[0].innerHTML.split('<br>')[1]}`;
            } else {
                dom[0].innerText = php_vars.i18n_9;
            }
        }
    }
})