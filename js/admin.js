jQuery(() => {
    let div = document.getElementById('wwa_log');
    if (div !== null) {
        div.scrollTop = div.scrollHeight;
        if (jQuery('#wwa-remove-log').length === 0) {
            setInterval(() => {
                updateLog();
            }, 5000);
        }
    }

    jQuery('input[name=user_verification]').on('change', () => {
        if (jQuery('input[name=user_verification]:checked').val() === 'false') {
            jQuery('#wwa-uv-field').after(`<div class="notice notice-warning" role="alert" id="wp-webauthn-uv-warning"><p>${php_vars.i18n_1}</p></div>`);
        } else {
            jQuery('#wp-webauthn-uv-warning').remove();
        }
    });

    setTimeout(() => {
        if (jQuery('input[name=user_verification]:checked').val() === 'false') {
            jQuery('#wwa-uv-field').after(`<div class="notice notice-warning" role="alert" id="wp-webauthn-uv-warning"><p>${php_vars.i18n_1}</p></div>`);
        }
    }, 0);

    const updateConditionalCreateTypeWarning = () => {
        const authenticatorType = jQuery('#allow_authenticator_type').val();
        const conditionalCreate = jQuery('#conditional_create').val();
        const shouldShow = authenticatorType && authenticatorType !== 'none' && conditionalCreate && conditionalCreate !== 'off';
        const warningId = 'wp-webauthn-conditional-create-type-warning';

        if (!shouldShow) {
            jQuery(`#${warningId}`).remove();
            return;
        }
        if (jQuery(`#${warningId}`).length !== 0) {
            return;
        }

        const warning = jQuery(`<p class="description" id="${warningId}"></p>`).text(php_vars.i18n_4);
        const description = jQuery('#wwa-conditional-create-description');
        if (description.length !== 0) {
            description.after(warning);
        } else {
            jQuery('#conditional_create').after(warning);
        }
    };
    jQuery('#allow_authenticator_type, #conditional_create').on('change', updateConditionalCreateTypeWarning);
    updateConditionalCreateTypeWarning();
})

// Update log
function updateLog() {
    if (jQuery('#wwa_log').length === 0) {
        return;
    }
    jQuery.ajax({
        url: php_vars.ajax_url,
        type: 'GET',
        data: {
            action: 'wwa_get_log',
            _ajax_nonce: php_vars._ajax_nonce
        },
        success: function (data) {
            if (typeof data === 'string') {
                console.warn(data);
                jQuery('#wwa_log').text(php_vars.i18n_3);
                return;
            }
            if (data.length === 0) {
                document.getElementById('clear_log').disabled = true;
                jQuery('#wwa_log').text('');
                jQuery('#wwa-remove-log').remove();
                jQuery('#log-count').text(php_vars.i18n_2 + '0');
                return;
            }
            document.getElementById('clear_log').disabled = false;
            let data_str = data.join('\n');
            if (data_str !== jQuery('#wwa_log').text()) {
                jQuery('#wwa_log').text(data_str);
                jQuery('#log-count').text(php_vars.i18n_2 + data.length);
                let div = document.getElementById('wwa_log');
                div.scrollTop = div.scrollHeight;
            }
        },
        error: function () {
            jQuery('#wwa_log').text(php_vars.i18n_3);
        }
    })
}

// Clear log
jQuery('#clear_log').click((e) => {
    e.preventDefault();
    document.getElementById('clear_log').disabled = true;
    jQuery.ajax({
        url: php_vars.ajax_url,
        type: 'GET',
        data: {
            action: 'wwa_clear_log',
            _ajax_nonce: php_vars._ajax_nonce
        },
        success: function () {
            updateLog();
        },
        error: function (data) {
            document.getElementById('clear_log').disabled = false;
            alert(`Error: ${data}`);
            updateLog();
        }
    })
})
