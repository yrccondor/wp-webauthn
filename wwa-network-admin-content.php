<?php
if(!defined('ABSPATH')){
    exit;
}

// Handle network options save
function wwa_handle_network_options_save(){
    if(!current_user_can('manage_network_options')){
        wp_die(esc_html__('You do not have sufficient permissions to access this page.'));
    }

    check_admin_referer('wwa_network_options_update', 'wwa_network_options_nonce');

    $res_id = wwa_generate_random_string(5);

    $post_first_choice = sanitize_text_field(wp_unslash($_POST['first_choice'] ?? 'true'));
    if(!in_array($post_first_choice, array('true', 'webauthn', 'false'), true)){
        $post_first_choice = 'true';
    }
    if($post_first_choice !== wwa_get_option('first_choice')){
        wwa_add_log($res_id, 'network first_choice: "'.wwa_get_option('first_choice').'"->"'.$post_first_choice.'"');
    }
    wwa_update_option('first_choice', $post_first_choice);

    $post_user_verification = sanitize_text_field(wp_unslash($_POST['user_verification'] ?? 'false'));
    if(!in_array($post_user_verification, array('true', 'false'), true)){
        $post_user_verification = 'false';
    }
    if($post_user_verification !== wwa_get_option('user_verification')){
        wwa_add_log($res_id, 'network user_verification: "'.wwa_get_option('user_verification').'"->"'.$post_user_verification.'"');
    }
    wwa_update_option('user_verification', $post_user_verification);

    $post_usernameless_login = sanitize_text_field(wp_unslash($_POST['usernameless_login'] ?? 'false'));
    if(!in_array($post_usernameless_login, array('true', 'false'), true)){
        $post_usernameless_login = 'false';
    }
    if($post_usernameless_login !== wwa_get_option('usernameless_login')){
        wwa_add_log($res_id, 'network usernameless_login: "'.wwa_get_option('usernameless_login').'"->"'.$post_usernameless_login.'"');
    }
    wwa_update_option('usernameless_login', $post_usernameless_login);

    $post_allow_type = sanitize_text_field(wp_unslash($_POST['allow_authenticator_type'] ?? 'none'));
    if(!in_array($post_allow_type, array('none', 'platform', 'cross-platform'), true)){
        $post_allow_type = 'none';
    }
    if($post_allow_type !== wwa_get_option('allow_authenticator_type')){
        wwa_add_log($res_id, 'network allow_authenticator_type: "'.wwa_get_option('allow_authenticator_type').'"->"'.$post_allow_type.'"');
    }
    wwa_update_option('allow_authenticator_type', $post_allow_type);

    $post_show_type = sanitize_text_field(wp_unslash($_POST['show_authenticator_type'] ?? 'false'));
    if(!in_array($post_show_type, array('true', 'false'), true)){
        $post_show_type = 'false';
    }
    if($post_show_type !== wwa_get_option('show_authenticator_type')){
        wwa_add_log($res_id, 'network show_authenticator_type: "'.wwa_get_option('show_authenticator_type').'"->"'.$post_show_type.'"');
    }
    wwa_update_option('show_authenticator_type', $post_show_type);

    $raw_ror = wp_unslash($_POST['ror_origins'] ?? '');
    $ror_lines = explode("\n", $raw_ror);
    $sanitized_ror = array();
    foreach($ror_lines as $line){
        $line = trim($line);
        if($line === ''){
            continue;
        }
        $parsed = wp_parse_url($line);
        if(isset($parsed['scheme']) && isset($parsed['host'])){
            $origin = $parsed['scheme'] . '://' . $parsed['host'];
            if(isset($parsed['port'])){
                $origin .= ':' . $parsed['port'];
            }
            $sanitized_ror[] = $origin;
        }
    }
    $post_ror_origins = implode("\n", $sanitized_ror);
    if($post_ror_origins !== wwa_get_option('ror_origins')){
        wwa_add_log($res_id, 'network ror_origins: "'.str_replace("\n", ', ', wwa_get_option('ror_origins')).'"->"'.str_replace("\n", ', ', $post_ror_origins).'"');
    }
    wwa_update_option('ror_origins', $post_ror_origins);

    wp_safe_redirect(add_query_arg('updated', 'true', network_admin_url('settings.php?page=wwa_network_admin')));
    exit;
}

// Display network settings page
function wwa_display_network_settings(){
    if(!current_user_can('manage_network_options')){
        wp_die(esc_html__('You do not have sufficient permissions to access this page.'));
    }

    wp_enqueue_script('wwa_admin', plugins_url('js/admin.js', __FILE__), array(), get_option('wwa_version')['version']);
    wp_localize_script('wwa_admin', 'php_vars', array(
        'ajax_url' => admin_url('admin-ajax.php'),
        '_ajax_nonce' => wp_create_nonce('wwa_admin_ajax'),
        'i18n_1' => __('User verification is disabled by default because some mobile devices do not support it (especially on Android devices). But we <strong>recommend you to enable it</strong> if possible to further secure your login.', 'wp-webauthn'),
        'i18n_2' => __('Log count: ', 'wp-webauthn'),
        'i18n_3' => __('Loading failed, maybe try refreshing?', 'wp-webauthn')
    ));
    wp_enqueue_style('wwa_admin', plugins_url('css/admin.css', __FILE__));

    $wwa_not_allowed = false;
    if(!function_exists('mb_substr') || !function_exists('gmp_intval') || !function_exists('sodium_crypto_sign_detached') || !wwa_check_ssl() && (wp_parse_url(site_url(), PHP_URL_HOST) !== 'localhost' && wp_parse_url(site_url(), PHP_URL_HOST) !== '127.0.0.1')){
        $wwa_not_allowed = true;
    }
    ?>

    <div class="wrap">
    <h1>WP-WebAuthn <?php esc_html_e('Network Settings', 'wp-webauthn');?></h1>

    <?php if(isset($_GET['updated']) && $_GET['updated'] === 'true'){ ?>
        <div class="notice notice-success is-dismissible"><p><?php esc_html_e('Settings saved.', 'wp-webauthn');?></p></div>
    <?php } ?>

    <p class="description"><?php esc_html_e('These settings apply to all sites in the network.', 'wp-webauthn');?></p>

    <form method="post" action="<?php echo esc_url(network_admin_url('edit.php?action=wwa_network_options_update')); ?>">
        <?php wp_nonce_field('wwa_network_options_update', 'wwa_network_options_nonce'); ?>
        <table class="form-table" role="presentation">
    <tr>
    <th scope="row"><label for="first_choice"><?php esc_html_e('Preferred login method', 'wp-webauthn');?></label></th>
    <td>
    <?php $wwa_v_first_choice=wwa_get_option('first_choice');?>
    <select name="first_choice" id="first_choice">
        <option value="true"<?php if($wwa_v_first_choice !== 'false' && !($wwa_v_first_choice === 'webauthn' && !$wwa_not_allowed)){?> selected<?php }?>><?php esc_html_e('Prefer WebAuthn', 'wp-webauthn');?></option>
        <option value="false"<?php if($wwa_v_first_choice === 'false'){?> selected<?php }?>><?php esc_html_e('Prefer password', 'wp-webauthn');?></option>
        <option value="webauthn"<?php if($wwa_v_first_choice === 'webauthn' && !$wwa_not_allowed){?> selected<?php }if($wwa_not_allowed){?> disabled<?php }?>><?php esc_html_e('WebAuthn Only', 'wp-webauthn');?></option>
    </select>
    <p class="description"><?php echo wp_kses(__('When using "WebAuthn Only", password login will be completely disabled. Please make sure your browser supports WebAuthn, otherwise you may unable to login.<br>User that doesn\'t have any registered authenticator (e.g. new user) will unable to login when using "WebAuthn Only".<br>When the browser does not support WebAuthn, the login method will default to password if password login is not disabled.', 'wp-webauthn'), array('br' => array()));?></p>
    </td>
    </tr>
    <tr>
    <th scope="row"></th>
    </tr>
    <tr>
    <th scope="row"><label for="user_verification"><?php esc_html_e('Require user verification', 'wp-webauthn');?></label></th>
    <td>
    <?php $wwa_v_uv=wwa_get_option('user_verification');?>
        <fieldset id="wwa-uv-field">
            <label><input type="radio" name="user_verification" value="true" <?php if($wwa_v_uv === 'true'){?>checked="checked"<?php }?>> <?php esc_html_e("Enable", "wp-webauthn");?></label><br>
            <label><input type="radio" name="user_verification" value="false" <?php if($wwa_v_uv === 'false'){?>checked="checked"<?php }?>> <?php esc_html_e("Disable", "wp-webauthn");?></label><br>
            <p class="description"><?php echo wp_kses(__('User verification can improve security, but is not fully supported by mobile devices. <br> If you cannot register or verify your authenticators, please consider disabling user verification.', 'wp-webauthn'), array('br' => array()));?></p>
        </fieldset>
    </td>
    </tr>
    <tr>
    <th scope="row"><label for="usernameless_login"><?php esc_html_e('Allow to login without username', 'wp-webauthn');?></label></th>
    <td>
    <?php $wwa_v_ul=wwa_get_option('usernameless_login');?>
        <fieldset>
            <label><input type="radio" name="usernameless_login" value="true" <?php if($wwa_v_ul === 'true'){?>checked="checked"<?php }?>> <?php esc_html_e("Enable", "wp-webauthn");?></label><br>
            <label><input type="radio" name="usernameless_login" value="false" <?php if($wwa_v_ul === 'false' || $wwa_v_ul === false){?>checked="checked"<?php }?>> <?php esc_html_e("Disable", "wp-webauthn");?></label><br>
            <p class="description"><?php echo wp_kses(__('Allow users to register authenticator with usernameless authentication feature and login without username.<br><strong>User verification will be enabled automatically when authenticating with usernameless authentication feature.</strong><br>Some authenticators and some browsers <strong>DO NOT</strong> support this feature.', 'wp-webauthn'), array('br' => array(), 'strong' => array()));?></p>
        </fieldset>
    </td>
    </tr>
    <tr>
    <th scope="row"><label for="allow_authenticator_type"><?php esc_html_e('Allow a specific type of authenticator', 'wp-webauthn');?></label></th>
    <td>
    <?php $wwa_v_at=wwa_get_option('allow_authenticator_type');?>
    <select name="allow_authenticator_type" id="allow_authenticator_type">
        <option value="none"<?php if($wwa_v_at === 'none' || $wwa_v_at === false){?> selected<?php }?>><?php esc_html_e('Any', 'wp-webauthn');?></option>
        <option value="platform"<?php if($wwa_v_at === 'platform'){?> selected<?php }?>><?php esc_html_e('Platform (e.g. Passkey or built-in sensors)', 'wp-webauthn');?></option>
        <option value="cross-platform"<?php if($wwa_v_at === 'cross-platform'){?> selected<?php }?>><?php esc_html_e('Roaming (e.g. USB security keys)', 'wp-webauthn');?></option>
    </select>
    <p class="description"><?php esc_html_e('If a type is selected, the browser will only prompt for authenticators of selected type when authenticating and user can only register authenticators of selected type.', 'wp-webauthn');?></p>
    </td>
    </tr>
    <tr>
    <th scope="row"><label for="show_authenticator_type"><?php esc_html_e('Allow users to choose authenticator type', 'wp-webauthn');?></label></th>
    <td>
    <?php $wwa_v_sat=wwa_get_option('show_authenticator_type');?>
        <fieldset>
            <label><input type="radio" name="show_authenticator_type" value="true" <?php if($wwa_v_sat === 'true'){?>checked="checked"<?php }?>> <?php esc_html_e("Enable", "wp-webauthn");?></label><br>
            <label><input type="radio" name="show_authenticator_type" value="false" <?php if($wwa_v_sat === 'false' || $wwa_v_sat === false){?>checked="checked"<?php }?>> <?php esc_html_e("Disable", "wp-webauthn");?></label><br>
            <p class="description"><?php echo wp_kses(__('When enabled, users can select the authenticator type when registering.<br>The "Allow a specific type" restriction above still applies regardless of this setting.', 'wp-webauthn'), array('br' => array()));?></p>
        </fieldset>
    </td>
    </tr>
    <tr>
    <th scope="row"></th>
    </tr>
    <!-- Feature not fully ready <tr>
    <th scope="row"><label for="ror_origins"><?php esc_html_e('Related origins', 'wp-webauthn');?></label></th>
    <td>
    <?php $wwa_v_ror = wwa_get_option('ror_origins');?>
        <textarea name="ror_origins" id="ror_origins" rows="4" cols="50" class="large-text code"><?php echo esc_textarea($wwa_v_ror ? $wwa_v_ror : '');?></textarea>
        <p class="description"><?php echo wp_kses(__('Allow cross-site passkey usages (<a href="https://passkeys.dev/docs/advanced/related-origins/" target="_blank">Related Origin Requests</a>). May be useful for multi-site networks.<br> Enter one origin per line (e.g. <code>https://example.com</code>). Leave empty to disable.', 'wp-webauthn'), array('a' => array('href' => array(), 'target' => array()), 'br' => array(), 'code' => array()));?></p>
    </td>
    </tr>-->
        </table>
        <?php submit_button(); ?>
    </form>
    </div>
    <?php
}
