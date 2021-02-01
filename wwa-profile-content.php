<?php
// Insert CSS and JS
wp_enqueue_script('wwa_profile', plugins_url('js/profile.js', __FILE__));
wp_localize_script('wwa_profile', 'php_vars', array(
    'ajax_url' => admin_url('admin-ajax.php'),
    'user_id' => $user->ID,
    'i18n_1' => __('Initializing...', 'wwa'),
    'i18n_2' => __('Please follow instructions to finish registration...', 'wwa'),
    'i18n_3' => '<span class="wwa-success">'._x('Registered', 'action', 'wwa').'</span>',
    'i18n_4' => '<span class="wwa-failed">'.__('Registration failed', 'wwa').'</span>',
    'i18n_5' => __('Your browser does not support WebAuthn', 'wwa'),
    'i18n_6' => __('Registrating...', 'wwa'),
    'i18n_7' => __('Please enter the authenticator identifier', 'wwa'),
    'i18n_8' => __('Loading failed, maybe try refreshing?', 'wwa'),
    'i18n_9' => __('Any', 'wwa'),
    'i18n_10' => __('Platform authenticator', 'wwa'),
    'i18n_11' => __('Roaming authenticator', 'wwa'),
    'i18n_12' => __('Remove', 'wwa'),
    'i18n_13' => __('Please follow instructions to finish verification...', 'wwa'),
    'i18n_14' => __('Verifying...', 'wwa'),
    'i18n_15' => '<span class="wwa-failed">'.__('Verification failed', 'wwa').'</span>',
    'i18n_16' => '<span class="wwa-success">'.__('Verification passed! You can now log in through WebAuthn', 'wwa').'</span>',
    'i18n_17' => __('No registered authenticators', 'wwa'),
    'i18n_18' => __('Confirm removal of authenticator: ', 'wwa'),
    'i18n_19' => __('Removing...', 'wwa'),
    'i18n_20' => __('Rename', 'wwa'),
    'i18n_21' => __('Rename the authenticator', 'wwa'),
    'i18n_22' => __('Renaming...', 'wwa'),
    'i18n_24' => __('Ready', 'wwa'),
    'i18n_25' => __('No', 'wwa'),
    'i18n_26' => __(' (Unavailable)', 'wwa'),
    'i18n_27' => __('The site administrator has disabled usernameless login feature.', 'wwa'),
    'i18n_28' => __('After removing this authenticator, you will not be able to login with WebAuthn', 'wwa'),
    'i18n_29' => __(' (Disabled)', 'wwa'),
    'i18n_30' => __('The site administrator only allow platform authenticators currently.', 'wwa'),
    'i18n_31' => __('The site administrator only allow roaming authenticators currently.', 'wwa')
));
wp_enqueue_style('wwa_profile', plugins_url('css/admin.css', __FILE__));
wp_localize_script('wwa_profile', 'configs', array('usernameless' => (wwa_get_option('usernameless_login') === false ? "false" : wwa_get_option('usernameless_login')), 'allow_authenticator_type' => (wwa_get_option('allow_authenticator_type') === false ? "none" : wwa_get_option('allow_authenticator_type'))));
?>
<br>
<h2 id="wwa-webauthn-start">WebAuthn</h2>
<table class="form-table">
<tr class="user-rich-editing-wrap">
    <th scope="row"><?php _e('WebAuthn Only', 'wwa');?></th>
        <td>
            <label for="webauthn_only">
                <?php $wwa_v_first_choice = wwa_get_option('first_choice');?>
                <input name="webauthn_only" type="checkbox" id="webauthn_only" value="true"<?php if($wwa_v_first_choice === 'webauthn'){echo ' disabled checked';}else{if(get_the_author_meta('webauthn_only', $user->ID) === 'true'){echo ' checked';}} ?>> <?php _e('Disable password login for this account', 'wwa');?>
            </label>
            <p class="description"><?php _e('When checked, password login will be completely disabled. Please make sure your browser supports WebAuthn and you have a registered authenticator, otherwise you may unable to login.', 'wwa');if($wwa_v_first_choice === 'webauthn'){?><br><strong><?php _e('The site administrator has disabled password login for the whole site.', 'wwa');?></strong><?php }?></p>
        </td>
    </tr>
</table>
<h3><?php _e('Registered WebAuthn Authenticators', 'wwa');?></h3>
<div class="wwa-table">
<table class="wp-list-table widefat fixed striped">
    <thead>
        <tr>
            <th><?php _e('Identifier', 'wwa');?></th>
            <th><?php _e('Type', 'wwa');?></th>
            <th><?php _ex('Registered', 'time', 'wwa');?></th>
            <th><?php _e('Last used', 'wwa');?></th>
            <th class="wwa-usernameless-th"><?php _e('Usernameless', 'wwa');?></th>
            <th><?php _e('Action', 'wwa');?></th>
        </tr>
    </thead>
    <tbody id="wwa-authenticator-list">
        <tr>
            <td colspan="5"><?php _e('Loading...', 'wwa');?></td>
        </tr>
    </tbody>
    <tfoot>
        <tr>
            <th><?php _e('Identifier', 'wwa');?></th>
            <th><?php _e('Type', 'wwa');?></th>
            <th><?php _ex('Registered', 'time', 'wwa');?></th>
            <th><?php _e('Last used', 'wwa');?></th>
            <th class="wwa-usernameless-th"><?php _e('Usernameless', 'wwa');?></th>
            <th><?php _e('Action', 'wwa');?></th>
      </tr>
    </tfoot>
</table>
</div>
<p id="wwa_usernameless_tip"></p>
<p id="wwa_type_tip"></p>
<button id="wwa-add-new-btn" class="button" title="<?php _e('Register New Authenticator', 'wwa');?>"><?php _e('Register New Authenticator', 'wwa');?></button>&nbsp;&nbsp;<button id="wwa-verify-btn" class="button" title="<?php _e('Verify Authenticator', 'wwa');?>"><?php _e('Verify Authenticator', 'wwa');?></button>
<div id="wwa-new-block">
<button class="button button-small wwa-cancel"><?php _e('Close');?></button>
<h2><?php _e('Register New Authenticator', 'wwa');?></h2>
<p class="description"><?php printf(__('You are about to associate an authenticator with the current account <strong>%s</strong>.<br>You can register multiple authenticators for an account.', 'wwa'), $user->user_login);?></p>
<table class="form-table">
<tr>
<th scope="row"><label for="wwa_authenticator_type"><?php _e('Type of authenticator', 'wwa');?></label></th>
<td>
<?php
$allowed_type = wwa_get_option('allow_authenticator_type') === false ? 'none' : wwa_get_option('allow_authenticator_type');
?>
<select name="wwa_authenticator_type" id="wwa_authenticator_type">
    <option value="none" id="type-none" class="sub-type"<?php if($allowed_type !== 'none'){echo ' disabled';}?>><?php _e('Any', 'wwa');?></option>
    <option value="platform" id="type-platform" class="sub-type"<?php if($allowed_type === 'cross-platform'){echo ' disabled';}?>><?php _e('Platform (e.g. built-in fingerprint sensors)', 'wwa');?></option>
    <option value="cross-platform" id="type-cross-platform" class="sub-type"<?php if($allowed_type === 'platform'){echo ' disabled';}?>><?php _e('Roaming (e.g. USB security keys)', 'wwa');?></option>
</select>
<p class="description"><?php _e('If a type is selected, the browser will only prompt for authenticators of selected type. <br> Regardless of the type, you can only log in with the very same authenticators you\'ve registered.', 'wwa');?></p>
</td>
</tr>
<tr>
<th scope="row"><label for="wwa_authenticator_name"><?php _e('Authenticator Identifier', 'wwa');?></label></th>
<td>
    <input name="wwa_authenticator_name" type="text" id="wwa_authenticator_name" class="regular-text">
    <p class="description"><?php _e('An easily identifiable name for the authenticator. <strong>DOES NOT</strong> affect the authentication process in anyway.', 'wwa');?></p>
</td>
</tr>
<?php if(wwa_get_option('usernameless_login') === "true"){?>
<tr>
<th scope="row"><label for="wwa_authenticator_usernameless"><?php _e('Login without username', 'wwa');?></th>
<td>
    <fieldset>
        <label><input type="radio" name="wwa_authenticator_usernameless" class="wwa_authenticator_usernameless" value="true"> <?php _e("Enable", "wwa");?></label><br>
        <label><input type="radio" name="wwa_authenticator_usernameless" class="wwa_authenticator_usernameless" value="false" checked="checked"> <?php _e("Disable", "wwa");?></label><br>
        <p class="description"><?php _e('If registered authenticator with this feature, you can login without enter your username.<br>Some authenticators like U2F-only authenticators and some browsers <strong>DO NOT</strong> support this feature.<br>A record will be stored in the authenticator permanently untill you reset it.', 'wwa');?></p>
    </fieldset>
</td>
</tr>
<?php }?>
</table>
<button id="wwa-bind" class="button"><?php _e('Start Registration', 'wwa');?></button>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="wwa-show-progress"></span>
</div>
<div id="wwa-verify-block">
<button class="button button-small wwa-cancel"><?php _e('Close');?></button>
<h2><?php _e('Verify Authenticator', 'wwa');?></h2>
<p class="description"><?php _e('Click Test Login to verify that the registered authenticators are working.', 'wwa');?></p>
<button id="wwa-test" class="button"><?php _e('Test Login', 'wwa');?></button>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="wwa-show-test"></span>
<?php if(wwa_get_option('usernameless_login') === "true"){?>
<br><br><button id="wwa-test_usernameless" class="button"><?php _e('Test Login (usernameless)', 'wwa');?></button>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="wwa-show-test-usernameless"></span>
<?php }?>
</div>