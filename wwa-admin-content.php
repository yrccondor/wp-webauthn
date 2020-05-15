<?php
// Insert CSS and JS
wp_enqueue_script('wwa_admin', plugins_url('js/admin.js',__FILE__));
wp_localize_script('wwa_admin', 'php_vars', array('ajax_url' => admin_url('admin-ajax.php'),'i18n_1' => __('Initializing...','wwa'),'i18n_2' => __('Please follow instructions to finish registration...','wwa'),'i18n_3' => '<span class="success">'._x('Registered', 'action','wwa').'</span>','i18n_4' => '<span class="failed">'.__('Registration failed','wwa').'</span>','i18n_5' => __('Your browser does not support WebAuthn','wwa'),'i18n_6' => __('Registrating...','wwa'),'i18n_7' => __('Please enter the authenticator identifier','wwa'),'i18n_8' => __('Loading failed, maybe try refreshing?','wwa'),'i18n_9' => __('Any','wwa'),'i18n_10' => __('Platform authenticator','wwa'),'i18n_11' => __('Roaming authenticator','wwa'),'i18n_12' => __('Remove','wwa'),'i18n_13' => __('Please follow instructions to finish verification...','wwa'),'i18n_14' => __('Verifying...','wwa'),'i18n_15' => '<span class="failed">'.__('Verification failed','wwa').'</span>','i18n_16' => '<span class="success">'.__('Verification passed! You can now log in through WebAuthn','wwa').'</span>','i18n_17' => __('No registered authenticators','wwa'),'i18n_18' => __('Confirm removal of authenticator: ','wwa'),'i18n_19' => __('Removing...','wwa'),'i18n_20' => __('Rename','wwa'),'i18n_21' => __('Rename the authenticator','wwa'),'i18n_22' => __('Renaming...','wwa'),'i18n_23' => __('Log count: ','wwa'),'i18n_24' => __('Ready','wwa'),'i18n_25' => __('No','wwa'),'i18n_26' => __(' (Unavailable)','wwa'),'i18n_27' => __('The site administrator has disabled usernameless login feature.','wwa'),'i18n_28' => __('After removing this authenticator, you will not be able to login with WebAuthn','wwa')));
wp_enqueue_style('wwa_admin', plugins_url('css/admin.css',__FILE__));
?>
<div class="wrap"><h1>WP-WebAuthn</h1>
<?php
if(!function_exists("gmp_intval")){
    add_settings_error("wwa_settings", "gmp_error", __("PHP extension gmp doesn't seem to exist, rendering WP-WebAuthn unable to function.", "wwa"));
}
if(!function_exists("mb_substr")){
    add_settings_error("wwa_settings", "mbstr_error", __("PHP extension mbstring doesn't seem to exist, rendering WP-WebAuthn unable to function.", "wwa"));
}
if(!(isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') && (parse_url(site_url(), PHP_URL_HOST) !== "localhost" && parse_url(site_url(), PHP_URL_HOST) !== "127.0.0.1")){
    add_settings_error("wwa_settings", "https_error", __("WebAuthn features are restricted to websites in secure contexts. Please make sure your website is served over HTTPS or locally with <code>localhost</code>.", "wwa"));
}
// Only admin can change settings
if((isset($_POST['wwa_ref']) && $_POST['wwa_ref'] === 'true') && check_admin_referer('wwa_options_update') && current_user_can('edit_plugins') && ($_POST['first_choice'] === "true" || $_POST['first_choice'] === "false") && ($_POST['user_verification'] === "true" || $_POST['user_verification'] === "false") && ($_POST['usernameless_login'] === "true" || $_POST['usernameless_login'] === "false") && ($_POST['logging'] === "true" || $_POST['logging'] === "false")){
    $res_id = wwa_generate_random_string(5);
    if(sanitize_text_field($_POST['logging']) === 'true' && wwa_get_option('logging') === 'false'){
        // Initialize log
        if(!function_exists("gmp_intval")){
            wwa_add_log($res_id, "Warning: PHP extension gmp not found", true);
        }
        if(!function_exists("mb_substr")){
            wwa_add_log($res_id, "Warning: PHP extension mbstring not found", true);
        }
        if(!(isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') && (parse_url(site_url(), PHP_URL_HOST) !== "localhost" && parse_url(site_url(), PHP_URL_HOST) !== "127.0.0.1")){
            wwa_add_log($res_id, "Warning: Not in security context", true);
        }
        wwa_add_log($res_id, "PHP Version => ".phpversion().", WordPress Version => ".get_bloginfo('version').", WP-WebAuthn Version => ".get_option('wwa_version')['version'], true);
        wwa_add_log($res_id, "Current config: first_choice => \"".wwa_get_option('first_choice')."\", website_name => \"".wwa_get_option('website_name')."\", website_domain => \"".wwa_get_option('website_domain')."\", user_verification => \"".wwa_get_option('user_verification')."\", usernameless_login => \"".wwa_get_option('usernameless_login')."\"", true);
        wwa_add_log($res_id, "Logger initialized", true);
    }
    wwa_update_option('logging', sanitize_text_field($_POST['logging']));
    $post_first_choice = sanitize_text_field($_POST['first_choice']);
    if($post_first_choice !== wwa_get_option('first_choice')){
        wwa_add_log($res_id, "first_choice: \"".wwa_get_option('first_choice')."\"->\"".$post_first_choice."\"");
    }
    wwa_update_option('first_choice', $post_first_choice);
    $post_website_name = sanitize_text_field($_POST['website_name']);
    if($post_website_name !== wwa_get_option('website_name')){
        wwa_add_log($res_id, "website_name: \"".wwa_get_option('website_name')."\"->\"".$post_website_name."\"");
    }
    wwa_update_option('website_name', $post_website_name);
    $post_website_domain = str_replace("https:", "", str_replace("/", "", sanitize_text_field($_POST['website_domain'])));
    if($post_website_domain !== wwa_get_option('website_domain')){
        wwa_add_log($res_id, "website_domain: \"".wwa_get_option('website_domain')."\"->\"".$post_website_domain."\"");
    }
    wwa_update_option('website_domain', $post_website_domain);
    $post_user_verification = sanitize_text_field($_POST['user_verification']);
    if($post_user_verification !== wwa_get_option('user_verification')){
        wwa_add_log($res_id, "user_verification: \"".wwa_get_option('user_verification')."\"->\"".$post_user_verification."\"");
    }
    wwa_update_option('user_verification', $post_user_verification);
    $post_usernameless_login = sanitize_text_field($_POST['usernameless_login']);
    if($post_usernameless_login !== wwa_get_option('usernameless_login')){
        wwa_add_log($res_id, "usernameless_login: \"".wwa_get_option('usernameless_login')."\"->\"".$post_usernameless_login."\"");
    }
    wwa_update_option('usernameless_login', $post_usernameless_login);
    add_settings_error("wwa_settings", "save_success", __("Settings saved.", "wwa"), "success");
}elseif((isset($_POST['wwa_ref']) && $_POST['wwa_ref'] === 'true')){
    add_settings_error("wwa_settings", "save_error", __("Settings NOT saved.", "wwa"));
}
settings_errors("wwa_settings");

wp_localize_script('wwa_admin', 'configs', array('usernameless' => (wwa_get_option('usernameless_login') === false ? "false" : wwa_get_option('usernameless_login'))));

// Only admin can change settings
if(current_user_can("edit_plugins")){ ?>
<form method="post" action="">
<?php
wp_nonce_field('wwa_options_update');
?>
<input type='hidden' name='wwa_ref' value='true'>
<table class="form-table">
<tr>
<th scope="row"><label for="first_choice"><?php _e('Preferred login method', 'wwa');?></label></th>
<td>
<?php $wwa_v_first_choice=wwa_get_option('first_choice');?>
    <fieldset>
    <label><input type="radio" name="first_choice" value="true" <?php if($wwa_v_first_choice=='true'){?>checked="checked"<?php }?>> <?php _e('WebAuthn', 'wwa');?></label><br>
    <label><input type="radio" name="first_choice" value="false" <?php if($wwa_v_first_choice=='false'){?>checked="checked"<?php }?>> <?php _e('Username + Password', 'wwa');?></label><br>
    <p class="description"><?php _e('Since WebAuthn hasn\'t been fully supported by all browsers, you can only choose the preferred (default) login method and <strong>CANNOT completely disable the traditional Username+Password method</strong><br>Regardless of the preferred method, you will be able to switch to the other with a switch button at the login page. <br> When the browser does not support WebAuthn, the login method will default to Username+Password.', 'wwa');?></p>
    </fieldset>
</td>
</tr>
<tr>
<th scope="row"><label for="website_name"><?php _e('Website identifier', 'wwa');?></label></th>
<td>
    <input required name="website_name" type="text" id="website_name" value="<?php echo wwa_get_option('website_name');?>" class="regular-text">
    <p class="description"><?php _e('This identifier is for identification purpose only and <strong>DOES NOT</strong> affect the authentication process in anyway.', 'wwa');?></p>
</td>
</tr>
<tr>
<th scope="row"><label for="website_domain"><?php _e('Website domain', 'wwa');?></label></th>
<td>
    <input required name="website_domain" type="text" id="website_domain" value="<?php echo wwa_get_option('website_domain');?>" class="regular-text">
    <p class="description"><?php _e('This field <strong>MUST</strong> be exactly the same with the current domain or parent domain.', 'wwa');?></p>
</td>
</tr>
<tr>
<th scope="row"><label for="user_verification"><?php _e('Require user verification', 'wwa');?></label></th>
<td>
<?php $wwa_v_uv=wwa_get_option('user_verification');?>
    <fieldset>
    <label><input type="radio" name="user_verification" value="true" <?php if($wwa_v_uv=='true'){?>checked="checked"<?php }?>> <?php _e("Enable", "wwa");?></label><br>
    <label><input type="radio" name="user_verification" value="false" <?php if($wwa_v_uv=='false'){?>checked="checked"<?php }?>> <?php _e("Disable", "wwa");?></label><br>
    <p class="description"><?php _e('User verification can improve security, but is not fully supported by mobile devices. <br> If you cannot register or verify your authenticators, please consider disabling user verification.', 'wwa');?></p>
    </fieldset>
</td>
</tr>
<tr>
<th scope="row"><label for="usernameless_login"><?php _e('Allow to login without username', 'wwa');?></label></th>
<td>
<?php $wwa_v_ul=wwa_get_option('usernameless_login');
if($wwa_v_ul === false){
    wwa_update_option('usernameless_login', 'false');
    $wwa_v_ul = 'false';
}
?>
    <fieldset>
    <label><input type="radio" name="usernameless_login" value="true" <?php if($wwa_v_ul=='true'){?>checked="checked"<?php }?>> <?php _e("Enable", "wwa");?></label><br>
    <label><input type="radio" name="usernameless_login" value="false" <?php if($wwa_v_ul=='false'){?>checked="checked"<?php }?>> <?php _e("Disable", "wwa");?></label><br>
    <p class="description"><?php _e('Allow users to register authenticator with usernameless authentication feature and login without username.<br><strong>User verification will be enabled automatically when registering authenticator with usernameless authentication feature.</strong>', 'wwa');?></p>
    </fieldset>
</td>
</tr>
<tr>
<th scope="row"><label for="logging"><?php _e('Logging', 'wwa');?></label></th>
<td>
<?php $wwa_v_log=wwa_get_option('logging');
if($wwa_v_log === false){
    wwa_update_option('logging', 'false');
    $wwa_v_log = 'false';
}
?>
    <fieldset>
    <label><input type="radio" name="logging" value="true" <?php if($wwa_v_log=='true'){?>checked="checked"<?php }?>> <?php _e("Enable", "wwa");?></label><br>
    <label><input type="radio" name="logging" value="false" <?php if($wwa_v_log=='false'){?>checked="checked"<?php }?>> <?php _e("Disable", "wwa");?></label><br>
    <p>
        <button id="clear_log" class="button" <?php $log = get_option('wwa_log');if($log === false || ($log !== false && count($log) === 0)){?> disabled<?php }?>><?php _e('Clear log', 'wwa');?></button>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="log-count"><?php echo __("Log count: ", "wwa").($log === false ? "0" : strval(count($log)));?></span>
    </p>
    <p class="description"><?php _e('For debugging only. Enable only when needed.<br><strong>Note: Logs may contain sensitive information.</strong>', 'wwa');?></p>
    </fieldset>
</td>
</tr>
</table><?php submit_button(); ?></form>
<?php
    if(wwa_get_option('logging') === 'true' || ($log !== false && count($log) > 0)){
?>
<div<?php if(wwa_get_option('logging') !== 'true'){?> id="wwa-remove-log"<?php }?>>
<h2><?php _e('Log', 'wwa');?></h2>
<textarea name="wwa_log" id="wwa_log" rows="15" cols="68" readonly><?php echo get_option("wwa_log") === false ? "" : implode("\n", get_option("wwa_log"));?></textarea>
<p class="description"><?php _e('Automatic update every 5 seconds.', 'wwa');?></p>
<br>
</div>
<?php }}?>
<br>
<h2><?php _e('Register Authenticator', 'wwa');?></h2>
<p class="description"><?php _e('You are about to associate an authenticator with <strong>the current account</strong>. You can register multiple authenticators for an account. <br> If you want to register authenticators for other users, please log in using that account.', 'wwa');?></p>
<table class="form-table">
<tr>
<th scope="row"><label for="authenticator_type"><?php _e('Type of authenticator', 'wwa');?></label></th>
<td>
<select name="authenticator_type" id="authenticator_type">
    <option value="none" id="type-none" class="sub-type"><?php _e('Any', 'wwa');?></option>
    <option value="platform" id="type-platform" class="sub-type"><?php _e('Platform authenticator (e.g. a built-in fingerprint sensor) only', 'wwa');?></option>
    <option value="cross-platform" id="type-cross-platform" class="sub-type"><?php _e('Roaming authenticator (e.g., a USB security key) only', 'wwa');?></option>
</select>
<p class="description"><?php _e('If a type is selected, the browser will only prompt for authenticators of selected type. <br> Regardless of the type, you can only log in with the very same authenticators you\'ve registered.', 'wwa');?></p>
</td>
</tr>
<tr>
<th scope="row"><label for="authenticator_name"><?php _e('Authenticator identifier', 'wwa');?></label></th>
<td>
    <input required name="authenticator_name" type="text" id="authenticator_name" class="regular-text">
    <p class="description"><?php _e('An easily identifiable name for the authenticator. <strong>DOES NOT</strong> affect the authentication process in anyway.', 'wwa');?></p>
</td>
</tr>
<?php if(wwa_get_option('usernameless_login') === "true"){?>
<tr>
<th scope="row"><label for="authenticator_usernameless"><?php _e('Login without username', 'wwa');?></th>
<td>
    <fieldset>
        <label><input type="radio" name="authenticator_usernameless" class="authenticator_usernameless" value="true"> <?php _e("Enable", "wwa");?></label><br>
        <label><input type="radio" name="authenticator_usernameless" class="authenticator_usernameless" value="false" checked="checked"> <?php _e("Disable", "wwa");?></label><br>
        <p class="description"><?php _e('If registered authenticator with this feature, you can login without enter your username.<br>Some devices like U2F-only devices and some browsers <strong>DO NOT</strong> support this feature.', 'wwa');?></p>
    </fieldset>
</td>
</tr>
<?php }?>
</table>
<p class="submit"><button id="bind" class="button button-primary"><?php _e('Start registration', 'wwa');?></button>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="show-progress"></span></p>
<h2><?php _e('Authenticators currently registered', 'wwa');?></h2>
<div class="wwa-table">
<table class="wp-list-table widefat fixed striped">
    <thead>
        <tr>
            <th><?php _e('Identifier', 'wwa');?></th>
            <th><?php _e('Type', 'wwa');?></th>
            <th><?php _ex('Registered', 'time', 'wwa');?></th>
            <th><?php _e('Last used', 'wwa');?></th>
            <th><?php _e('Usernameless', 'wwa');?></th>
            <th><?php _e('Action', 'wwa');?></th>
        </tr>
    </thead>
    <tbody id="authenticator-list">
        <tr>
            <td colspan="6"><?php _e('Loading...', 'wwa');?></td>
        </tr>
    </tbody>
    <tfoot>
        <tr>
            <th><?php _e('Identifier', 'wwa');?></th>
            <th><?php _e('Type', 'wwa');?></th>
            <th><?php _ex('Registered', 'time', 'wwa');?></th>
            <th><?php _e('Last used', 'wwa');?></th>
            <th><?php _e('Usernameless', 'wwa');?></th>
            <th><?php _e('Action', 'wwa');?></th>
      </tr>
    </tfoot>
</table>
</div>
<p id="usernameless_tip"></p>
<br>
<h2><?php _e('Verify registration', 'wwa');?></h2>
<p class="description"><?php _e('Click verify to verify that the registered authenticators are working.', 'wwa');?></p>
<p class="submit"><button id="test" class="button button-primary"><?php _e('Verify', 'wwa');?></button>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="show-test"></span>
<?php if(wwa_get_option('usernameless_login') === "true"){?>
<br><br><button id="test_usernameless" class="button button-primary"><?php _e('Verify (usernameless)', 'wwa');?></button>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="show-test-usernameless"></span>
<?php }?></p>
</div>