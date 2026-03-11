<?php
// Two Factor
if(!defined('ABSPATH')) {
    exit;
}

if(!function_exists('wwa_is_webauthn_ajax_login_request')) {
    function wwa_is_webauthn_ajax_login_request(): bool {
        if(!function_exists('wp_doing_ajax') || !wp_doing_ajax()) {
            return false;
        }

        $action = isset($_REQUEST['action'])
            ? sanitize_text_field(wp_unslash($_REQUEST['action']))
            : '';

        return in_array($action, array('wwa_auth_start', 'wwa_auth'), true);
    }
}

if(wwa_is_webauthn_ajax_login_request() && class_exists('Two_Factor_Core')) {
    // Prevent Two-Factor from redirecting passwordless WebAuthn logins
    // into its own wp_login challenge flow.
    // Two-Factor < 0.15 registered at priority 10; >= 0.15 at PHP_INT_MAX.
    // Use has_action() to handle any priority automatically.
    $prio = has_action('wp_login', array('Two_Factor_Core', 'wp_login'));
    if($prio !== false) {
        remove_action('wp_login', array('Two_Factor_Core', 'wp_login'), $prio);
    }

    // Prevent Two-Factor from treating the user as a 2FA user during the
    // WebAuthn AJAX auth flow. This keeps Two-Factor fully active for
    // normal password logins, while ensuring its wp_login handler
    // returns early without showing a challenge if it fires for any reason.
    add_filter('two_factor_enabled_providers_for_user', function($_enabled, $_user_id) {
        return array();
    }, 9, 2);
}
