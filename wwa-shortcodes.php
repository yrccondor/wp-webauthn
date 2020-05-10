<?php
require_once('vendor/autoload.php');
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;

function wwa_localize_frontend(){
    wp_enqueue_script('wwa_frontend_js', plugins_url('js/frontend.js',__FILE__), array(), get_option('wwa_version')['version'], true);
    wp_localize_script('wwa_frontend_js', 'wwa_php_vars', array('ajax_url' => admin_url('admin-ajax.php'),'admin_url' => admin_url(),'i18n_2' => __('Authenticate with WebAuthn','wwa'),'i18n_3' => __('Hold on...','wwa'),'i18n_4' => __('Please proceed...','wwa'),'i18n_5' => __('Authenticating...','wwa'),'i18n_6' => '<span class="wwa-success">'.__('Authenticated','wwa'),'i18n_7' => '<span class="wwa-failed">'.__('Auth failed','wwa').'</span>','i18n_11' => __('Error: The username field is empty.','wwa'),'i18n_12' => __('Please enter the authenticator identifier','wwa'),'i18n_13' => __('Please follow instructions to finish verification...','wwa'),'i18n_14' => __('Verifying...','wwa'),'i18n_15' => '<span class="failed">'.__('Verification failed','wwa').'</span>','i18n_16' => '<span class="success">'.__('Verification passed! You can now log in through WebAuthn','wwa').'</span>','i18n_17' => __('Loading failed, maybe try refreshing?','wwa'),'i18n_18' => __('Confirm removal of authenticator: ','wwa'),'i18n_19' => __('Removing...','wwa'),'i18n_20' => __('Rename','wwa'),'i18n_21' => __('Rename the authenticator','wwa'),'i18n_22' => __('Renaming...','wwa'),'i18n_23' => __('No registered authenticators','wwa'),'i18n_24' => __('Any','wwa'),'i18n_25' => __('Platform authenticator','wwa'),'i18n_26' => __('Roaming authenticator','wwa'),'i18n_27' => __('Remove','wwa'),'i18n_28' => __('Please follow instructions to finish registration...','wwa'),'i18n_29' => '<span class="success">'._x('Registered', 'action','wwa').'</span>','i18n_30' => '<span class="failed">'.__('Registration failed','wwa').'</span>','i18n_31' => __('Your browser does not support WebAuthn','wwa'),'i18n_32' => __('Registrating...','wwa')));
}

// Login form
function wwa_login_form_shortcode($vals){
    extract(shortcode_atts(
        array(
            'traditional' => 'true',
            'username' => '',
            'auto_hide' => 'true',
            'to' => ''
        ), $vals)
    );

    if($auto_hide === "true" && current_user_can("read")){
        return '';
    }

    // Load Javascript & CSS
    if(!wp_script_is('wwa_frontend_js')){
        wwa_localize_frontend();
    }
    // wp_enqueue_script('wwa_frontend_js');
    wp_enqueue_style('wwa_frondend_css', plugins_url('css/frontend.css',__FILE__), array(), get_option('wwa_version')['version']);

    $html_form = '<div class="wwa-login-form">';

    $args = array('echo' => false, 'value_username' => $username);
    $to_wwa = "";
    if($to !== ""){
        $args["redirect"] = $to;
        if(substr($to, 0, 7) !== "http://" && substr($to, 0, 8) !== "https://" && substr($to, 0, 6) !== "ftp://" && substr($to, 0, 7) !== "mailto:"){
            $to_wwa = '<input type="hidden" name="wwa-redirect-to" class="wwa-redirect-to" id="wwa-redirect-to" value="http://'.$to.'">';
        }else{
            $to_wwa = '<input type="hidden" name="wwa-redirect-to" class="wwa-redirect-to" id="wwa-redirect-to" value="'.$to.'">';
        }
    }

    if($traditional === "true"){
        $html_form .= '<div class="wwa-login-form-traditional">'.wp_login_form($args).'<p class="wwa-t2w"><span>'.__('Authenticate with WebAuthn','wwa').'</span></p></div>';
    }

    $html_form .= '<div class="wwa-login-form-webauthn"><p class="wwa-login-username"><label for="wwa-user-name">'.__('Username','wwa').'</label><input type="text" name="wwa-user-name" id="wwa-user-name" class="wwa-user-name" value="'.$username.'" size="20"></p><div class="wp-webauthn-notice">'.__('Authenticate with WebAuthn','wwa').'</div><p class="wwa-login-submit-p"><input type="button" name="wwa-login-submit" id="wwa-login-submit" class="wwa-login-submit button button-primary" value="'.__('Auth','wwa').'">'.$to_wwa.'<span class="wwa-w2t">'.__('Authenticate with password','wwa').'</span></p></div></div>';

    return $html_form;
}
add_shortcode('wwa_login_form', 'wwa_login_form_shortcode');

// Register form
function wwa_register_form_shortcode($vals){
    extract(shortcode_atts(
        array(
            'display' => 'true'
        ), $vals)
    );

    // If always display
    if(!current_user_can("read")){
        if($display === "true"){
            return '<div class="wwa-register-form"><p class="wwa-bind">'.__('You haven\'t logged in yet.', 'wwa').'</p></div>';
        }else{
            return '';
        }
    }

    // Load Javascript & CSS
    if(!wp_script_is('wwa_frontend_js')){
        wwa_localize_frontend();
    }
    wp_enqueue_style('wwa_frondend_css', plugins_url('css/frontend.css',__FILE__), array(), get_option('wwa_version')['version']);

    return '<div class="wwa-register-form"><label for="wwa-authenticator-type">'.__('Type of authenticator', 'wwa').'</label><select name="wwa-authenticator-type" class="wwa-authenticator-type" id="wwa-authenticator-type"><option value="none" class="wwa-type-none">'.__('Any', 'wwa').'</option><option value="platform" class="wwa-type-platform">'.__('Platform authenticator (e.g. a built-in fingerprint sensor) only', 'wwa').'</option><option value="cross-platform" class="wwa-type-cross-platform">'.__('Roaming authenticator (e.g., a USB security key) only', 'wwa').'</option></select><p class="wwa-bind-name-description">'.__('If a type is selected, the browser will only prompt for authenticators of selected type. <br> Regardless of the type, you can only log in with the very same authenticators you\'ve registered.', 'wwa').'</p><label for="wwa-authenticator-name">'.__('Authenticator identifier', 'wwa').'</label><input required name="wwa-authenticator-name" type="text" class="wwa-authenticator-name" id="wwa-authenticator-name"><p class="wwa-bind-name-description">'.__('An easily identifiable name for the authenticator. <strong>DOES NOT</strong> affect the authentication process in anyway.', 'wwa').'</p><p class="wwa-bind"><button class="wwa-bind-submit">'.__('Start registration', 'wwa').'</button>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="wwa-show-progress"></span></p></div>';
}
add_shortcode('wwa_register_form', 'wwa_register_form_shortcode');

// Verify button
function wwa_verify_button_shortcode($vals){
    extract(shortcode_atts(
        array(
            'display' => 'true'
        ), $vals)
    );

    // If always display
    if(!current_user_can("read")){
        if($display === "true"){
            return '<p class="wwa-test">'.__('You haven\'t logged in yet.', 'wwa').'</p>';
        }else{
            return '';
        }
    }

    // Load Javascript
    if(!wp_script_is('wwa_frontend_js')){
        wwa_localize_frontend();
    }

    return '<p class="wwa-test"><button class="wwa-test-submit">'.__('Verify', 'wwa').'</button>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="wwa-show-test"></span></p>';
}
add_shortcode('wwa_verify_button', 'wwa_verify_button_shortcode');

// Authenticator list
function wwa_list_shortcode($vals){
    extract(shortcode_atts(
        array(
            'display' => 'true'
        ), $vals)
    );

    $thead = '<table class="wwa-list-table"><thead><tr><th>'.__('Identifier', 'wwa').'</th><th>'.__('Type', 'wwa').'</th><th>'._x('Registered', 'time', 'wwa').'</th><th>'.__('Action', 'wwa').'</th></tr></thead><tbody class="wwa-authenticator-list">';
    $tfoot = '</tbody><tfoot><tr><th>'.__('Identifier', 'wwa').'</th><th>'.__('Type', 'wwa').'</th><th>'._x('Registered', 'time', 'wwa').'</th><th>'.__('Action', 'wwa').'</th></tr></tfoot></table>';
    

    // If always display
    if(!current_user_can("read")){
        if($display === "true"){
            // Load CSS
            wp_enqueue_style('wwa_frondend_css', plugins_url('css/frontend.css',__FILE__), array(), get_option('wwa_version')['version']);

            return $thead.'<tr><td colspan="4">'.__('You haven\'t logged in yet', 'wwa').'</td></tr>'.$tfoot;
        }else{
            return '';
        }
    }

    // Load Javascript & CSS
    if(!wp_script_is('wwa_frontend_js')){
        wwa_localize_frontend();
    }
    wp_enqueue_style('wwa_frondend_css', plugins_url('css/frontend.css',__FILE__), array(), get_option('wwa_version')['version']);

    $user_info = wp_get_current_user();

    $user_key = "";
    if(!isset(wwa_get_option("user_id")[$user_info->user_login])){
        // The user haven't bound any authenticator, return empty list
        return $thead.'<tr><td colspan="4">'.__('No registered authenticators', 'wwa').'</td></tr>'.$tfoot;
    }else{
        $user_key = wwa_get_option("user_id")[$user_info->user_login];
    }

    $userEntity = new PublicKeyCredentialUserEntity(
        $user_info->user_login,
        $user_key,
        $user_info->display_name
    );

    $publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();
    $authenticator_list = $publicKeyCredentialSourceRepository->getShowList($userEntity);
    $html_list = "";
    foreach($authenticator_list as $item){
        $html_list .= '<tr><td>'.$item["name"].'</td><td>'.($item["type"] === "none" ? __('Rename', 'wwa') : ($item["type"] === __('Any', 'wwa') ? __('Platform authenticator', 'wwa') : __('Roaming authenticator', 'wwa'))).'</td><td>'.$item["added"].'</td><td class="wwa-key-'.$item["key"].'"><a href="javascript:renameAuthenticator(\''.$item["key"].'\', \''.$item["name"].'\')">'.__('Rename', 'wwa').'</a> | <a href="javascript:removeAuthenticator(\''.$item["key"].'\', \''.$item["name"].'\')">'.__('Remove', 'wwa').'</a></td></tr>';
    }
    return $thead.$html_list.$tfoot;
}
add_shortcode('wwa_list', 'wwa_list_shortcode');
?>