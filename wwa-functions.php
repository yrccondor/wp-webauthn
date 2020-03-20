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
    wp_localize_script('wwa_login', 'php_vars', array('ajax_url' => admin_url('admin-ajax.php'),'admin_url' => admin_url(),'i18n_1' => __('认证','wwa'),'i18n_2' => __('使用 WebAuthn 认证','wwa'),'i18n_3' => __('请稍候...','wwa'),'i18n_4' => __('请按提示完成认证...','wwa'),'i18n_5' => __('正在认证...','wwa'),'i18n_6' => '<span class="wwa-success"><span class="dashicons dashicons-yes"></span> '.__('登录成功','wwa').'</span>','i18n_7' => '<span class="wwa-failed"><span class="dashicons dashicons-no-alt"></span> '.__('认证失败','wwa').'</span>','i18n_8' => __('请填写用户名','wwa'),'i18n_9' => __('用户名','wwa'),'i18n_10' => __('用户名或电子邮件地址','wwa'),'i18n_11' => __('<strong>错误</strong>：用户名一栏为空。','wwa')));
    if(wwa_get_option('first_choice') === 'true'){
        wp_enqueue_script('wwa_default', plugins_url('js/default_wa.js',__FILE__), array('jquery'), '1.0.0', true);
    }
    wp_enqueue_style('wwa_login_css', plugins_url('css/login.css',__FILE__));
}
add_action('login_enqueue_scripts', 'wwa_login_js');

// Multi-language support
function wwa_load_textdomain(){
    load_plugin_textdomain('wwa', false, dirname(plugin_basename(__FILE__)).'/languages');
}
add_action('init', 'wwa_load_textdomain');
?>