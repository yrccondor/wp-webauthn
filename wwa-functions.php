<?php
if (!defined('ABSPATH')) {
    exit;
}

// WordPress transient adapter
function wwa_set_temp_val($name, $value, $client_id){
    return set_transient('wwa_'.$name.$client_id, serialize($value), 90);
}

function wwa_get_temp_val($name, $client_id){
    $val = get_transient('wwa_'.$name.$client_id);
    return $val === false ? false : maybe_unserialize($val);
}

function wwa_delete_temp_val($name, $client_id){
    return delete_transient('wwa_'.$name.$client_id);
}

// Destroy all transients
function wwa_destroy_temp_val($client_id){
    wwa_delete_temp_val('user_name_auth', $client_id);
    wwa_delete_temp_val('user_auth', $client_id);
    wwa_delete_temp_val('pkcco', $client_id);
    wwa_delete_temp_val('bind_config', $client_id);
    wwa_delete_temp_val('pkcco_auth', $client_id);
    wwa_delete_temp_val('usernameless_auth', $client_id);
    wwa_delete_temp_val('auth_type', $client_id);
}

// Destroy all transients before wp_die
function wwa_wp_die($message = '', $client_id = false){
    if($client_id !== false){
        wwa_destroy_temp_val($client_id);
    }
    wp_die(esc_html($message));
}

// Init data for new options
function wwa_init_new_options(){
    if(wwa_get_option('allow_authenticator_type') === false){
        wwa_update_option('allow_authenticator_type', 'none');
    }
    // Existing installs default to 'true' to preserve previous behaviour
    if(wwa_get_option('show_authenticator_type') === false){
        wwa_update_option('show_authenticator_type', 'true');
    }
    if(wwa_get_option('remember_me') === false){
        wwa_update_option('remember_me', 'false');
    }
    if(wwa_get_option('email_login') === false){
        wwa_update_option('email_login', 'false');
    }
    if(wwa_get_option('usernameless_login') === false){
        wwa_update_option('usernameless_login', 'false');
    }
    if(wwa_get_option('password_reset') === false){
        wwa_update_option('password_reset', 'off');
    }
    if(wwa_get_option('after_user_registration') === false){
        wwa_update_option('after_user_registration', 'none');
    }
    if(wwa_get_option('terminology') === false){
        wwa_update_option('terminology', 'webauthn');
    }
    if(wwa_get_option('ror_origins') === false){
        wwa_update_option('ror_origins', '');
    }
}

// Create random strings for user ID
function wwa_generate_random_string($length = 10){
    // Use cryptographically secure pseudo-random generator in PHP 7+
    if(function_exists('random_bytes')){
        $bytes = random_bytes(round($length/2));
        return bin2hex($bytes);
    }else{
        // Not supported, use normal random generator instead
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_';
        $randomString = '';
        for($i = 0; $i < $length; $i++){
            $randomString .= $characters[wp_rand(0, strlen($characters) - 1)];
        }
        return $randomString;
    }
}

// Add log
function wwa_add_log($id, $content = '', $init = false){
    if(wwa_get_option('logging') !== 'true' && !$init){
        return;
    }
    $log = get_option('wwa_log');
    if($log === false){
        $log = array();
    }
    $log[] = '['.current_time('mysql').']['.$id.'] '.wp_strip_all_tags($content);
    update_option('wwa_log', $log);
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

    for($i = 0; $i < $length; $i++){
        $result[] = ($i + 1).')'.substr($trace[$i], strpos($trace[$i], ' '));
    }

    return "Traceback:\n                              ".implode("\n                              ", $result);
}

function wwa_cleanup_blog_credentials($user_id, $blog_id){
    global $wpdb;
    $wpdb->delete($wpdb->wwa_credentials, array(
        'user_id' => $user_id,
        'registered_blog_id' => $blog_id
    ));
}

function wwa_cleanup_all_user_credentials($user_id){
    global $wpdb;
    $wpdb->delete($wpdb->wwa_credentials, array('user_id' => $user_id));
    delete_user_meta($user_id, 'wwa_user_handle');
    delete_user_meta($user_id, 'wwa_webauthn_only');
}

function wwa_delete_user($user_id){
    $res_id = wwa_generate_random_string(5);

    $user_data = get_userdata($user_id);
    if($user_data !== false){
        wwa_add_log($res_id, "Deleted user credentials for => \"".$user_data->user_login."\"");
    }

    if(is_multisite()){
        wwa_cleanup_blog_credentials($user_id, get_current_blog_id());
    }else{
        wwa_cleanup_all_user_credentials($user_id);
    }
}
add_action('delete_user', 'wwa_delete_user');

function wwa_delete_user_multisite($user_id){
    $res_id = wwa_generate_random_string(5);

    $user_data = get_userdata($user_id);
    if($user_data !== false){
        wwa_add_log($res_id, "Deleted all user credentials for => \"".$user_data->user_login."\" (network deletion)");
    }

    wwa_cleanup_all_user_credentials($user_id);
}
add_action('wpmu_delete_user', 'wwa_delete_user_multisite');

function wwa_remove_user_from_blog($user_id, $blog_id){
    $res_id = wwa_generate_random_string(5);

    $user_data = get_userdata($user_id);
    if($user_data !== false){
        wwa_add_log($res_id, "Deleted user credentials for => \"".$user_data->user_login."\" (removed from blog ".$blog_id.")");
    }

    wwa_cleanup_blog_credentials($user_id, $blog_id);
}
add_action('remove_user_from_blog', 'wwa_remove_user_from_blog', 10, 2);

// Add CSS and JS in login page
function wwa_login_js(){
    wwa_init_new_options();

    $wwa_not_allowed = false;
    if(!function_exists('mb_substr') || !function_exists('gmp_intval') || !wwa_check_ssl() && (wp_parse_url(site_url(), PHP_URL_HOST) !== 'localhost' && wp_parse_url(site_url(), PHP_URL_HOST) !== '127.0.0.1')){
        $wwa_not_allowed = true;
    }
    wp_enqueue_script('wwa_login', plugins_url('js/login.js', __FILE__), array(), get_option('wwa_version')['version'], true);
    $first_choice = wwa_get_option('first_choice');
    wp_localize_script('wwa_login', 'wwa_login_php_vars', array(
        'ajax_url' => admin_url('admin-ajax.php'),
        'admin_url' => admin_url(),
        'usernameless' => (wwa_get_option('usernameless_login') === false ? 'false' : wwa_get_option('usernameless_login')),
        'remember_me' => (wwa_get_option('remember_me') === false ? 'false' : wwa_get_option('remember_me')),
        'email_login' => (wwa_get_option('email_login') === false ? 'false' : wwa_get_option('email_login')),
        'allow_authenticator_type' => (wwa_get_option('allow_authenticator_type') === false ? "none" : wwa_get_option('allow_authenticator_type')),
        'webauthn_only' => ($first_choice === 'webauthn' && !$wwa_not_allowed) ? 'true' : 'false',
        'password_reset' => ((wwa_get_option('password_reset') === false || wwa_get_option('password_reset') === 'off') ? 'false' : 'true'),
        'separator' => apply_filters('login_link_separator', ' | '),
        'terminology' => (wwa_get_option('terminology') === false ? 'passkey' : wwa_get_option('terminology')),
        'i18n_1' => __('Auth', 'wp-webauthn'),
        'i18n_2' => wwa_get_option('terminology') === 'webauthn' ? __('Authenticate with WebAuthn', 'wp-webauthn') : __('Authenticate with a passkey', 'wp-webauthn'),
        'i18n_3' => __('Hold on...', 'wp-webauthn'),
        'i18n_4' => __('Please proceed...', 'wp-webauthn'),
        'i18n_5' => __('Authenticating...', 'wp-webauthn'),
        'i18n_6' => '<span class="wwa-success"><span class="dashicons dashicons-yes"></span> '.__('Authenticated', 'wp-webauthn').'</span>',
        'i18n_7' => '<span class="wwa-failed"><span class="dashicons dashicons-no-alt"></span> '.__('Auth failed', 'wp-webauthn').'</span>',
        'i18n_8' => __('It looks like your browser doesn\'t support WebAuthn, which means you may unable to login.', 'wp-webauthn'),
        'i18n_9' => __('Username', 'wp-webauthn'),
        'i18n_10' => __('Username or Email Address'),
        'i18n_11' => __('<strong>Error</strong>: The username field is empty.', 'wp-webauthn'),
        'i18n_12' => '<span class="wwa-try-username">'.__('Try to enter the username', 'wp-webauthn').'</span>',
        'i18n_13' => __('Password'),
        'i18n_14' => wwa_get_option('terminology') === 'webauthn' ? 'WebAuthn' : __('Passkey', 'wp-webauthn')
    ));
    if($first_choice === 'true' || $first_choice === 'webauthn'){
        wp_enqueue_script('wwa_default', plugins_url('js/default_wa.js', __FILE__), array(), get_option('wwa_version')['version'], true);
    }
    wp_enqueue_style('wwa_login_css', plugins_url('css/login.css', __FILE__), array(), get_option('wwa_version')['version']);
}
add_action('login_enqueue_scripts', 'wwa_login_js', 999);

// Disable password login
function wwa_disable_password($user){
    if(!function_exists('mb_substr') || !function_exists('gmp_intval') || !wwa_check_ssl() && (wp_parse_url(site_url(), PHP_URL_HOST) !== 'localhost' && wp_parse_url(site_url(), PHP_URL_HOST) !== '127.0.0.1')){
        return $user;
    }
    if(wwa_get_option('first_choice') === 'webauthn'){
        return new WP_Error('wwa_password_disabled', __('Logging in with password has been disabled by the site manager.', 'wp-webauthn'));
    }
    if(is_wp_error($user)){
        return $user;
    }
    if(get_user_meta($user->ID, 'wwa_webauthn_only', true) === 'true'){
        return new WP_Error('wwa_password_disabled_for_account', __('Logging in with password has been disabled for this account.', 'wp-webauthn'));
    }
    return $user;
}
add_filter('wp_authenticate_user', 'wwa_disable_password', 10, 1);

function wwa_handle_user_register($user_id){
    if(wwa_get_option('password_reset') === 'admin' || wwa_get_option('password_reset') === 'all'){
        update_user_option($user_id, 'default_password_nag', false);
    }
    if(wwa_get_option('after_user_registration') === 'login'){
        wp_set_current_user($user_id);
        wp_set_auth_cookie($user_id);
        wp_redirect(admin_url('profile.php?wwa_registered=true#wwa-webauthn-start'));
        exit;
    }
}
add_action('register_new_user', 'wwa_handle_user_register');

// Disable Password Reset URL & Redirect
function wwa_disable_lost_password(){
    if((wwa_get_option('password_reset') === 'admin' || wwa_get_option('password_reset') === 'all') && isset($_GET['action'])){
        if(in_array($_GET['action'], array('lostpassword', 'retrievepassword', 'resetpass', 'rp'))){
            wp_redirect(wp_login_url(), 302);
            exit;
        }
    }
}
function wwa_handle_lost_password_html_link($link){
    if(wwa_get_option('password_reset') === 'admin' || wwa_get_option('password_reset') === 'all'){
        return '<span id="wwa-lost-password-link-placeholder"></span>';
    }
    return $link;
}
function wwa_handle_password(){
    if(wwa_get_option('password_reset') === 'admin' || wwa_get_option('password_reset') === 'all'){
        if(wwa_get_option('password_reset') === 'admin'){
            if(current_user_can('edit_users')){
                return true;
            }
        }
        return false;
    }
    return true;
}
if(wwa_get_option('password_reset') === 'admin' || wwa_get_option('password_reset') === 'all'){
    add_action('login_init', 'wwa_disable_lost_password');
    add_filter('lost_password_html_link', 'wwa_handle_lost_password_html_link');
    add_filter('show_password_fields', 'wwa_handle_password');
    add_filter('allow_password_reset', 'wwa_handle_password');
}

function wwa_no_authenticator_warning(){
    if(is_network_admin()){
        return;
    }

    $user_info = wp_get_current_user();
    $first_choice = wwa_get_option('first_choice');
    $check_self = true;
    if($first_choice !== 'webauthn' && get_user_meta($user_info->ID, 'wwa_webauthn_only', true) !== 'true'){
        $check_self = false;
    }

    if($check_self){
        global $wpdb;
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->wwa_credentials}
             WHERE user_id = %d AND registered_blog_id = %d",
            $user_info->ID, get_current_blog_id()
        ));
        if(intval($count) === 0){ ?>
            <div class="notice notice-warning">
                <?php /* translators: %s: 'the site' or 'your account', 'WebAuthn authenticator' or 'passkey', and admin profile url */ ?>
                <p><?php echo wp_kses(sprintf(__('Logging in with password has been disabled for %1$s but you haven\'t register any %2$s on the current site yet. You may unable to login again once you log out. <a href="%3$s#wwa-webauthn-start">Register</a>', 'wp-webauthn'), esc_html($first_choice === 'webauthn' ? __('the site', 'wp-webauthn') : __('your account', 'wp-webauthn')), esc_html(wwa_get_option('terminology') === 'webauthn' ? __('WebAuthn authenticator', 'wp-webauthn') : __('passkey', 'wp-webauthn')), esc_url(admin_url('profile.php'))), array('a' => array('href' => array())));?></p>
                <?php if(is_multisite() && !is_subdomain_install()){
                    /* translators: %s: 'WebAuthn authenticators' or 'Passkeys' */ ?>
                <p><?php echo esc_html(sprintf(__('%s registered on other sites within this network may also be used to log in.', 'wp-webauthn'), wwa_get_option('terminology') === 'webauthn' ? __('WebAuthn authenticators', 'wp-webauthn') : __('Passkeys', 'wp-webauthn'))); ?></p>
                <?php } ?>
            </div>
        <?php }
    }

    global $pagenow;
    if($pagenow == 'user-edit.php' && isset($_GET['user_id']) && intval($_GET['user_id']) !== $user_info->ID){
        $user_id_wp = intval($_GET['user_id']);
        if($user_id_wp <= 0 || !current_user_can('edit_user', $user_id_wp)){
            return;
        }
        $other_user = get_user_by('id', $user_id_wp);
        if($other_user === false){
            return;
        }
        if($first_choice !== 'webauthn' && get_user_meta($other_user->ID, 'wwa_webauthn_only', true) !== 'true'){
            return;
        }

        global $wpdb;
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->wwa_credentials}
             WHERE user_id = %d AND registered_blog_id = %d",
            $other_user->ID, get_current_blog_id()
        ));
        if(intval($count) === 0){ ?>
            <div class="notice notice-warning">
                <?php /* translators: %s: 'the site' or 'your account', and 'WebAuthn authenticator' or 'passkey' */ ?>
                <p><?php echo wp_kses(sprintf(__('Logging in with password has been disabled for %1$s but <strong>this account</strong> haven\'t register any %2$s on the current site yet. This user may unable to login.', 'wp-webauthn'), esc_html($first_choice === 'webauthn' ? __('the site', 'wp-webauthn') : __('this account', 'wp-webauthn')), esc_html(wwa_get_option('terminology') === 'webauthn' ? __('WebAuthn authenticator', 'wp-webauthn') : __('passkey', 'wp-webauthn'))), array('strong' => array()));?></p>
                <?php if(is_multisite() && !is_subdomain_install()){
                    /* translators: %s: 'WebAuthn authenticators' or 'Passkeys' */ ?>
                <p><?php echo esc_html(sprintf(__('%s registered on other sites within this network may also be used to log in.', 'wp-webauthn'), wwa_get_option('terminology') === 'webauthn' ? __('WebAuthn authenticators', 'wp-webauthn') : __('Passkeys', 'wp-webauthn'))); ?></p>
                <?php } ?>
            </div>
        <?php }
    }
}
add_action('admin_notices', 'wwa_no_authenticator_warning');

// Load Gutenberg block assets
function wwa_load_blocks(){
  wp_enqueue_script(
        'wwa_block_js',
        plugins_url('blocks/blocks.build.js', __FILE__),
        ['wp-blocks', 'wp-i18n', 'wp-element', 'wp-editor'],
        true
  );
  wp_set_script_translations('wwa_block_js', 'wp-webauthn', plugin_dir_path(__FILE__).'blocks/languages');
}
add_action('enqueue_block_editor_assets', 'wwa_load_blocks');

// Multi-language support
function wwa_load_textdomain(){
    load_plugin_textdomain('wp-webauthn', false, dirname(plugin_basename(__FILE__)).'/languages');
}
add_action('init', 'wwa_load_textdomain');

// Add meta links in plugin list page
function wwa_settings_link($links_array, $plugin_file_name){
    if($plugin_file_name === 'wp-webauthn/wp-webauthn.php'){
        $links_array[] = '<a href="options-general.php?page=wwa_admin">'.__('Settings', 'wp-webauthn').'</a>';
    }
    return $links_array;
}
add_filter('plugin_action_links', 'wwa_settings_link', 10, 2);

function wwa_network_settings_link($links_array, $plugin_file_name){
    if($plugin_file_name === 'wp-webauthn/wp-webauthn.php'){
        $links_array[] = '<a href="'.esc_url(network_admin_url('settings.php?page=wwa_network_admin')).'">'.__('Network Settings', 'wp-webauthn').'</a>';
    }
    return $links_array;
}
if(is_multisite()){
    add_filter('network_admin_plugin_action_links', 'wwa_network_settings_link', 10, 2);
}

function wwa_meta_link($links_array, $plugin_file_name){
    if($plugin_file_name === 'wp-webauthn/wp-webauthn.php'){
        $links_array[] = '<a href="https://github.com/yrccondor/wp-webauthn">'.__('GitHub', 'wp-webauthn').'</a>';
        $links_array[] = '<a href="https://doc.flyhigher.top/wp-webauthn">'.__('Documentation', 'wp-webauthn').'</a>';
    }
    return $links_array;
}
add_filter('plugin_row_meta', 'wwa_meta_link', 10, 2);

// Check if we are under HTTPS
function wwa_check_ssl(){
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' && $_SERVER['HTTPS'] !== '') {
        return true;
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https' || !empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] === 'on') {
        return true;
    }
    if (isset($_SERVER['SERVER_PROTOCOL']) && $_SERVER['SERVER_PROTOCOL'] === 'HTTP/3.0') {
        return true;
    }
    if (isset($_SERVER['REQUEST_SCHEME']) && ($_SERVER['REQUEST_SCHEME'] === 'quic' || $_SERVER['REQUEST_SCHEME'] === 'https')) {
        return true;
    }
    return false;
}

// Check user privileges
function wwa_validate_privileges(){
    return current_user_can('manage_options');
}

// Get Related Origins Request list
function wwa_get_ror_list(){
    $raw = wwa_get_option('ror_origins');
    if($raw === false || $raw === ''){
        return array();
    }
    $origins = array();
    $lines = explode("\n", $raw);
    foreach($lines as $line){
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
            $origins[] = $origin;
        }
    }
    return $origins;
}

// Get user by username or email
function wwa_get_user($username){
    if(wwa_get_option('email_login') !== 'true'){
        return get_user_by('login', $username);
    }else{
        if(is_email($username)){
            return get_user_by('email', $username);
        }
        return get_user_by('login', $username);
    }
}

// Provide plugin version for other plugins
function wwa_loaded_version(){
    if(!get_option('wwa_version')){
        return '0.0.1';
    }
    return get_option('wwa_version')['version'];
}

// Register query vars
function wwa_query_vars($vars) {
    $vars[] = 'wwa-well-known-ror';
    return $vars;
}

// Add rewrite rules for .well-known/webauthn
function wwa_add_rewrite_rules() {
    add_rewrite_rule('^\.well-known/webauthn$', 'index.php?wwa-well-known-ror=true', 'top');
}
function wwa_apply_rewrite_rules() {
    wwa_add_rewrite_rules();
    flush_rewrite_rules();
}

// Handle .well-known/webauthn
function wwa_handle_ror($wp) {
    if (array_key_exists('wwa-well-known-ror', $wp->query_vars)) {
        header('Content-Type: application/json');
        header('Access-Control-Allow-Origin: *');
        echo wp_json_encode(array(
            'origins'=> wwa_get_ror_list()
        ));
        exit;
    }
}

// Initialize plugin data for a new site created in a multisite network
function wwa_new_site_init($new_site){
    $network_active = get_site_option('active_sitewide_plugins');
    if(isset($network_active['wp-webauthn/wp-webauthn.php'])){
        switch_to_blog($new_site->id);
        wwa_init_data();
        wwa_apply_rewrite_rules();
        restore_current_blog();
    }
}
add_action('wp_initialize_site', 'wwa_new_site_init');

add_filter('query_vars', 'wwa_query_vars');
add_action('parse_request', 'wwa_handle_ror', 99);
add_action('init', 'wwa_add_rewrite_rules', 1);
