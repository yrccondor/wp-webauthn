<?php
// Start session
function wwa_register_session(){
    if(!session_id()){
        session_start();
    }
}
add_action('init','wwa_register_session');

// Destroy all sessions when user state changes
function wwa_destroy_session() {
    unset($_SESSION['wwa_user_name_auth']);
    unset($_SESSION['wwa_user_auth']);
    unset($_SESSION['wwa_server']);
    unset($_SESSION['wwa_pkcco']);
    unset($_SESSION['wwa_server_auth']);
    unset($_SESSION['wwa_pkcco_auth']);
}
add_action('wp_logout', 'wwa_destroy_session');
add_action('wp_login', 'wwa_destroy_session');

// Create random strings for user ID
function wwa_generate_random_string($length = 10) {
    // Use cryptographically secure pseudo-random generator in PHP 7+
    if(function_exists("random_bytes")){
        $bytes = random_bytes(round($length/2));
        return bin2hex($bytes);
    }else{
        // Not supported, use normal random generator instead
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'; 
        $randomString = ''; 
        for ($i = 0; $i < $length; $i++) { 
            $randomString .= $characters[rand(0, strlen($characters) - 1)]; 
        } 
        return $randomString; 
    }
}

// Add CSS and JS in login page
function wwa_login_js() {
    wp_enqueue_script('wwa_login', plugins_url('js/login.js',__FILE__), array('jquery'), '1.0.0', true);
    wp_localize_script('wwa_login', 'php_vars', array('ajax_url' => admin_url('admin-ajax.php'),'admin_url' => admin_url(),'i18n_1' => __('Auth','wwa'),'i18n_2' => __('Authenticate with WebAuthn','wwa'),'i18n_3' => __('Hold on...','wwa'),'i18n_4' => __('Please proceed...','wwa'),'i18n_5' => __('Authenticating...','wwa'),'i18n_6' => '<span class="wwa-success"><span class="dashicons dashicons-yes"></span> '.__('Authenticated','wwa').'</span>','i18n_7' => '<span class="wwa-failed"><span class="dashicons dashicons-no-alt"></span> '.__('Auth failed','wwa').'</span>','i18n_9' => __('Username','wwa'),'i18n_10' => __('Username or Email Address','wwa'),'i18n_11' => __('<strong>Error</strong>: The username field is empty.','wwa')));
    if(wwa_get_option('first_choice') === 'true'){
        wp_enqueue_script('wwa_default', plugins_url('js/default_wa.js',__FILE__), array('jquery'), '1.0.0', true);
    }
    wp_enqueue_style('wwa_login_css', plugins_url('css/login.css',__FILE__));
}
add_action('login_enqueue_scripts', 'wwa_login_js', 999);

// Multi-language support
function wwa_load_textdomain(){
    load_plugin_textdomain('wwa', false, dirname(plugin_basename(__FILE__)).'/languages');
}
add_action('init', 'wwa_load_textdomain');

function wwa_settings_link($links_array, $plugin_file_name){
    if($plugin_file_name === "wp-webauthn/wp-webauthn.php"){
        $links_array[] = '<a href="options-general.php?page=wwa_admin">'.__("Settings", "wwa").'</a>';
    }
    return $links_array;
}
add_filter('plugin_action_links', 'wwa_settings_link', 10, 2);

function wwa_meta_link($links_array, $plugin_file_name){
    if($plugin_file_name === "wp-webauthn/wp-webauthn.php"){
        $links_array[] = '<a href="https://github.com/yrccondor/wp-webauthn">'.__("GitHub", "wwa").'</a>';
    }
    return $links_array;
}
add_filter('plugin_row_meta', 'wwa_meta_link', 10, 2);
?>