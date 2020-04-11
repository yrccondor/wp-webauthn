<?php
// Insert CSS and JS
wp_enqueue_script('wwa_admin', plugins_url('js/admin.js',__FILE__));
wp_localize_script('wwa_admin', 'php_vars', array('ajax_url' => admin_url('admin-ajax.php'),'i18n_1' => __('Initializing...','wwa'),'i18n_2' => __('Please follow instructions to finish registration...','wwa'),'i18n_3' => '<span class="success">'.__('Registered','wwa').'</span>','i18n_4' => '<span class="failed">'.__('Registration failed','wwa').'</span>','i18n_5' => __('Your browser does not support WebAuthn','wwa'),'i18n_6' => __('Registrating...','wwa'),'i18n_7' => __('Please enter the authenticator identifier','wwa'),'i18n_8' => __('Loading failed, maybe try refreshing?','wwa'),'i18n_9' => __('Any','wwa'),'i18n_10' => __('Platform authenticator','wwa'),'i18n_11' => __('Roaming authenticator','wwa'),'i18n_12' => __('Delete','wwa'),'i18n_13' => __('Please follow instructions to finish verification...','wwa'),'i18n_14' => __('Verifying...','wwa'),'i18n_15' => '<span class="failed">'.__('Verification failed','wwa').'</span>','i18n_16' => '<span class="success">'.__('Verification passed! You can now log in through WebAuthn','wwa').'</span>','i18n_17' => __('No registered authenticators','wwa'),'i18n_18' => __('Confirm removal of authenticator: ','wwa'),'i18n_19' => __('Removing...','wwa')));
wp_enqueue_style('wwa_admin', plugins_url('css/admin.css',__FILE__));
?>
<div class="wrap"><h1>WP-WebAuthn</h1>
<?php
if(!function_exists("gmp_intval")){
    add_settings_error("wwa_settings", "gmp_error", __("PHP gmp extension doesn't seem to exist, rendering WP-WebAuthn unable to function.", "wwa"));
}
if(!(isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') && (explode(":", explode("/", explode("//", site_url())[1])[0])[0] !== "localhost")){
    add_settings_error("wwa_settings", "https_error", __("WebAuthn features are restricted to websites in secure contexts. Please make sure your website is served over HTTPS or locally with <code>localhost</code>.", "wwa"));
}
// Only admin can change settings
if((isset($_POST['wwa_ref']) && $_POST['wwa_ref'] === 'true') && check_admin_referer('wwa_options_update') && current_user_can('edit_plugins') && ($_POST['first_choice'] === "true" || $_POST['first_choice'] === "false") && ($_POST['user_verification'] === "true" || $_POST['user_verification'] === "false")){
    wwa_update_option('first_choice', sanitize_text_field($_POST['first_choice']));
    wwa_update_option('website_name', sanitize_text_field($_POST['website_name']));
    wwa_update_option('website_domain', str_replace("https:", "", str_replace("/", "", sanitize_text_field($_POST['website_domain']))));
    wwa_update_option('user_verification', sanitize_text_field($_POST['user_verification']));
    add_settings_error("wwa_settings", "save_success", __("Settings saved.", "wwa"), "success");
}elseif((isset($_POST['wwa_ref']) && $_POST['wwa_ref'] === 'true')){
    add_settings_error("wwa_settings", "save_error", __("Settings NOT saved.", "wwa"));
}
settings_errors("wwa_settings");
// Only admin can change settings
if(current_user_can("edit_plugins")){ ?>
<form method="post" action="">
<?php
wp_nonce_field('wwa_options_update');
?>
<input type='hidden' name='wwa_ref' value='true'>
<table class="form-table">
<tr>
<th scope="row"><label for="first_choice"><?php _e('Preferred login method', 'wwa');?></lable></th>
<td>
<?php $wwa_v_first_choice=wwa_get_option('first_choice');?>
    <fieldset>
    <label><input type="radio" name="first_choice" value="true" <?php if($wwa_v_first_choice=='true'){?>checked="checked"<?php }?>> <?php _e('WebAuthn', 'wwa');?></label><br>
    <label><input type="radio" name="first_choice" value="false" <?php if($wwa_v_first_choice=='false'){?>checked="checked"<?php }?>> <?php _e('Username + Password', 'wwa');?></label><br>
    <p class="description"><?php _e('Since WebAuthn hasn\'t been fully supported by all browsers, you can only choose the preferred (default) login method and <strong>CANNOT completely disable the traditional Username+Password method</strong><br>Regardless of the preferred method, you will be able to switch to the other with a switch button at the login page. <br> When the browser does not support WebAuthn, the login method will default to Username+Password."', 'wwa');?></p>
    </fieldset>
</td>
</tr>
<tr>
<th scope="row"><label for="website_name"><?php _e('Website identifier', 'wwa');?></lable></th>
<td>
    <input required name="website_name" type="text" id="website_name" value="<?php echo wwa_get_option('website_name');?>" class="regular-text">
    <p class="description"><?php _e('This identifier is for identification purpose only and <strong>DOES NOT</strong> affect the authentication process in anyway.', 'wwa');?></p>
</td>
</tr>
<tr>
<th scope="row"><label for="website_domain"><?php _e('Website domain', 'wwa');?></lable></th>
<td>
    <input required name="website_domain" type="text" id="website_domain" value="<?php echo wwa_get_option('website_domain');?>" class="regular-text">
    <p class="description"><?php _e('This field <strong>MUST</strong> be exactly the same with the current domain or parent domain.', 'wwa');?></p>
</td>
</tr>
<tr>
<th scope="row"><?php _e('Require user verification', 'wwa');?></th>
<td>
<?php $wwa_v_uv=wwa_get_option('user_verification');?>
    <fieldset>
    <label><input type="radio" name="user_verification" value="true" <?php if($wwa_v_uv=='true'){?>checked="checked"<?php }?>> <?php _e("Enable", "wwa");?></label><br>
    <label><input type="radio" name="user_verification" value="false" <?php if($wwa_v_uv=='false'){?>checked="checked"<?php }?>> <?php _e("Disable", "wwa");?></label><br>
    <p class="description"><?php _e('User verification can improve security, but is not fully supported by mobile devices. <br> If you cannot register or verify your authenticators, please consider disabling user verification.', 'wwa');?></p>
    </fieldset>
</td>
</tr>
</table><?php submit_button(); ?></form>
<?php }?>
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
<th scope="row"><label for="authenticator_name"><?php _e('Authenticator identifier', 'wwa');?></lable></th>
<td>
    <input required name="authenticator_name" type="text" id="authenticator_name" class="regular-text">
    <p class="description"><?php _e('An easily identifiable name for the authenticator. <strong>DOES NOT</strong> affect the authentication process in anyway.', 'wwa');?></p>
</td>
</tr>
</table>
<p class="submit"><button id="bind" class="button button-primary"><?php _e('Start registration', 'wwa');?></button>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="show-progress"></span></p>
<h2><?php _e('Authenticators currently registered', 'wwa');?></h2>
<table class="wp-list-table widefat fixed striped">
    <thead>
        <tr>
            <th><?php _e('Identifier', 'wwa');?></th>
            <th><?php _e('Type', 'wwa');?></th>
            <th><?php _e('Registered', 'wwa');?></th>
            <th><?php _e('Action', 'wwa');?></th>
        </tr>
    </thead>
    <tbody id="authenticator-list">
        <tr>
            <td colspan="4"><?php _e('Loading...', 'wwa');?></td>
        </tr>
    </tbody>
    <tfoot>
        <tr>
            <th><?php _e('Identifier', 'wwa');?></th>
            <th><?php _e('Type', 'wwa');?></th>
            <th><?php _e('Registered', 'wwa');?></th>
            <th><?php _e('Action', 'wwa');?></th>
      </tr>
    </tfoot>
</table>
<br>
<h2><?php _e('Verify registration', 'wwa');?></h2>
<p class="description"><?php _e('Click verify to verify that the registered authenticators are working', 'wwa');?></p>
<p class="submit"><button id="test" class="button button-primary"><?php _e('Verify', 'wwa');?></button>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="show-test"></span></p>
</div>