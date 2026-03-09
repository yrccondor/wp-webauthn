<?php
// Two Factor
if (!defined('ABSPATH')) {
	exit;
}

if (!function_exists('wwa_is_webauthn_ajax_login_request')) {
	function wwa_is_webauthn_ajax_login_request(): bool {
		if (!function_exists('wp_doing_ajax') || !wp_doing_ajax()) {
			return false;
		}

		$action = isset($_REQUEST['action'])
			? sanitize_text_field(wp_unslash($_REQUEST['action']))
			: '';

		return in_array($action, array('wwa_auth_start', 'wwa_auth'), true);
	}
}

if (wwa_is_webauthn_ajax_login_request() && class_exists('Two_Factor_Core')) {

	/**
	 * 1) Prevent Two-Factor from redirecting passwordless WebAuthn logins
	 *    into its own wp_login challenge flow.
	 */
	$prio = has_action('wp_login', array('Two_Factor_Core', 'wp_login'));
	if ($prio !== false) {
		remove_action('wp_login', array('Two_Factor_Core', 'wp_login'), $prio);
	}

	// Defensive cleanup for common / unexpected priorities.
	remove_action('wp_login', array('Two_Factor_Core', 'wp_login'), 1);
	remove_action('wp_login', array('Two_Factor_Core', 'wp_login'), 10);
	remove_action('wp_login', array('Two_Factor_Core', 'wp_login'), 100);
	remove_action('wp_login', array('Two_Factor_Core', 'wp_login'), PHP_INT_MAX);

	/**
	 * 2) Prevent Two-Factor from reporting enabled providers during
	 *    the passwordless WebAuthn AJAX auth flow only.
	 *
	 * This keeps Two-Factor fully active for normal password logins.
	 */
	add_filter('two_factor_enabled_providers_for_user', function ($enabled, $user_id) {
		return array();
	}, 9, 2);

	/**
	 * 3) If Two-Factor previously blocked auth cookies in this request,
	 *    allow them again so WP-WebAuthn can complete login successfully.
	 */
	$cookie_prio = has_filter('send_auth_cookies', '__return_false');
	if ($cookie_prio !== false) {
		remove_filter('send_auth_cookies', '__return_false', $cookie_prio);
	}

	remove_filter('send_auth_cookies', '__return_false', 31);
	remove_filter('send_auth_cookies', '__return_false', 100);
	remove_filter('send_auth_cookies', '__return_false', PHP_INT_MAX);
}
