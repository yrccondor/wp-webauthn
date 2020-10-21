<?php
// Destroy all sessions when user state changes
function wwa_destroy_session(){
    unset($_SESSION['wwa_user_name_auth']);
    unset($_SESSION['wwa_user_auth']);
    unset($_SESSION['wwa_server']);
    unset($_SESSION['wwa_pkcco']);
    unset($_SESSION['wwa_bind_config']);
    unset($_SESSION['wwa_server_auth']);
    unset($_SESSION['wwa_pkcco_auth']);
    unset($_SESSION['wwa_usernameless_auth']);
    unset($_SESSION['wwa_auth_type']);
}
add_action('wp_logout', 'wwa_destroy_session');
add_action('wp_login', 'wwa_destroy_session');

// Destroy all sessions before wp_die
function wwa_wp_die($message = ""){
    wwa_destroy_session();
    wp_die($message);
}

// Create random strings for user ID
function wwa_generate_random_string($length = 10){
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

// Add log
function wwa_add_log($id, $content = "", $init = false){
    if(wwa_get_option("logging") !== "true" && !$init){
        return;
    }
    $log = get_option("wwa_log");
    if($log === false){
        $log = array();
    }
    $log[] = "[".date('Y-m-d H:i:s', current_time('timestamp'))."][".$id."] ".$content;
    update_option("wwa_log", $log);
}

// Format trackback
function wwa_generate_call_trace($exception = false){
    $e = $exception;
    if($exception === false){
        $e = new Exception();
    }
    $trace = explode("\n", $e->getTraceAsString());
    $trace = array_reverse($trace);
    array_shift($trace);
    array_pop($trace);
    $length = count($trace);
    $result = array();
   
    for ($i = 0; $i < $length; $i++)
    {
        $result[] = ($i + 1)  . ')' . substr($trace[$i], strpos($trace[$i], ' '));
    }
   
    return "Traceback:\n                              ".implode("\n                              ", $result);
}

// Delete all credentials when deleting user
function wwa_delete_user($user_id){
    $res_id = wwa_generate_random_string(5);

    $user_data = get_userdata($user_id);
    $all_user_meta = wwa_get_option("user_id");
    $user_key = "";
    wwa_add_log($res_id, "Delete user => \"".$user_data->user_login."\"");

    // Delete user meta
    foreach($all_user_meta as $user => $id){
        if($user === $user_data->user_login){
            $user_key = $id;
            wwa_add_log($res_id, "Delete user_key => \"".$id."\"");
            unset($all_user_meta[$user]);
        }
    }

    // Delete credentials
    $all_credentials_meta = json_decode(wwa_get_option("user_credentials_meta"), true);
    $all_credentials = json_decode(wwa_get_option("user_credentials"), true);
    foreach($all_credentials_meta as $credential => $meta){
        if($user_key === $meta["user"]){
            wwa_add_log($res_id, "Delete credential => \"".$credential."\"");
            unset($all_credentials_meta[$credential]);
            unset($all_credentials[$credential]);
        }
    }
    wwa_update_option("user_id", $all_user_meta);
    wwa_update_option("user_credentials_meta", json_encode($all_credentials_meta));
    wwa_update_option("user_credentials", json_encode($all_credentials));
    wwa_add_log($res_id, "Done");
}
add_action('delete_user', 'wwa_delete_user');

// Add CSS and JS in login page
function wwa_login_js() {
    wp_enqueue_script('wwa_login', plugins_url('js/login.js',__FILE__), array(), get_option('wwa_version')['version'], true);
    wp_localize_script('wwa_login', 'php_vars', array('ajax_url' => admin_url('admin-ajax.php'),'admin_url' => admin_url(),'usernameless' => (wwa_get_option('usernameless_login') === false ? "false" : wwa_get_option('usernameless_login')),'remember_me' => (wwa_get_option('remember_me') === false ? "false" : wwa_get_option('remember_me')),'i18n_1' => __('Auth','wwa'),'i18n_2' => __('Authenticate with WebAuthn','wwa'),'i18n_3' => __('Hold on...','wwa'),'i18n_4' => __('Please proceed...','wwa'),'i18n_5' => __('Authenticating...','wwa'),'i18n_6' => '<span class="wwa-success"><span class="dashicons dashicons-yes"></span> '.__('Authenticated','wwa').'</span>','i18n_7' => '<span class="wwa-failed"><span class="dashicons dashicons-no-alt"></span> '.__('Auth failed','wwa').'</span>','i18n_9' => __('Username','wwa'),'i18n_10' => __('Username or Email Address','wwa'),'i18n_11' => __('<strong>Error</strong>: The username field is empty.','wwa'),'i18n_12' => '<br><span class="wwa-try-username">'.__('Try to enter the username','wwa').'</span>'));
    if(wwa_get_option('first_choice') === 'true'){
        wp_enqueue_script('wwa_default', plugins_url('js/default_wa.js',__FILE__), array(), get_option('wwa_version')['version'], true);
    }
    wp_enqueue_style('wwa_login_css', plugins_url('css/login.css',__FILE__), array(), get_option('wwa_version')['version']);
}
add_action('login_enqueue_scripts', 'wwa_login_js', 999);

// Multi-language support
function wwa_load_textdomain(){
    load_plugin_textdomain('wwa', false, dirname(plugin_basename(__FILE__)).'/languages');
}
add_action('init', 'wwa_load_textdomain');

// Add meta links in plugin list page
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
        $links_array[] = '<a href="http://doc.flyhigher.top/wp-webauthn">'.__("Documentation", "wwa").'</a>';
    }
    return $links_array;
}
add_filter('plugin_row_meta', 'wwa_meta_link', 10, 2);
?>