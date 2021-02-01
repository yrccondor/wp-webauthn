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
            action: 'wwa_get_log'
        },
        success: function (data) {
            if (typeof data === 'string') {
                console.warn(data);
                jQuery('#wwa_log').text(php_vars.i18n_8);
                return;
            }
            if (data.length === 0) {
                document.getElementById('clear_log').disabled = true;
                jQuery('#wwa_log').text('');
                jQuery('#wwa-remove-log').remove();
                jQuery('#log-count').text(php_vars.i18n_23 + '0');
                return;
            }
            document.getElementById('clear_log').disabled = false;
            let data_str = data.join('\n');
            if (data_str !== jQuery('#wwa_log').text()) {
                jQuery('#wwa_log').text(data_str);
                jQuery('#log-count').text(php_vars.i18n_23 + data.length);
                let div = document.getElementById('wwa_log');
                div.scrollTop = div.scrollHeight;
            }
        },
        error: function () {
            jQuery('#wwa_log').text(php_vars.i18n_8);
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
            action: 'wwa_clear_log'
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