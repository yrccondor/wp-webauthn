<?php
/*
Plugin Name: WP-WebAuthn
Plugin URI: https://flyhigher.top
Description: WP-WebAuthn allows you to safely login to your WordPress site without password.
Version: 2.0.0
Author: Axton
Author URI: https://axton.cc
License: GPLv3
Text Domain: wp-webauthn
Domain Path: /languages
Network: true
Requires PHP: 8.2
*/
/* Copyright 2020 Axton
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version  of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
*/

if (!defined('ABSPATH')) {
    exit;
}

const WWA_NETWORK_OPTION_NAMES = array(
    'first_choice', 'ror_origins', 'ror_origins_normalized', 'user_verification',
    'usernameless_login', 'allow_authenticator_type', 'show_authenticator_type',
    'allow_profile_test', 'conditional_create', 'credential_scope'
);

function wwa_register_table() {
    global $wpdb;
    $wpdb->wwa_credentials = $wpdb->base_prefix . 'wwa_credentials';
}
wwa_register_table();
add_action('plugins_loaded', 'wwa_register_table', 0);

register_activation_hook(__FILE__, 'wwa_init');
register_uninstall_hook(__FILE__, 'wwa_uninstall');

function wwa_init(){
    if(version_compare(get_bloginfo('version'), '5.0', '<')){
        deactivate_plugins(basename(__FILE__));
        return;
    }
    if(is_multisite()){
        $sites = get_sites(array('fields' => 'ids', 'number' => 0));
        foreach($sites as $blog_id){
            switch_to_blog($blog_id);
            wwa_init_data();
            wwa_apply_rewrite_rules();
            restore_current_blog();
        }
    }else{
        wwa_init_data();
    }
}

function wwa_uninstall(){
    global $wpdb;

    if(is_multisite()){
        $sites = get_sites(array('fields' => 'ids', 'number' => 0));
        foreach($sites as $blog_id){
            switch_to_blog($blog_id);
            wwa_uninstall_site();
            restore_current_blog();
        }
        delete_site_option('wwa_network_options');
        delete_site_option(wwa_credentials_schema_option_name());
    }else{
        wwa_uninstall_site();
        delete_option(wwa_credentials_schema_option_name());
    }

    $wpdb->query("DROP TABLE IF EXISTS {$wpdb->wwa_credentials}");
    $wpdb->delete($wpdb->usermeta, array('meta_key' => 'wwa_user_handle'));
    $wpdb->delete($wpdb->usermeta, array('meta_key' => 'wwa_webauthn_only'));
}

function wwa_uninstall_site(){
    delete_option('wwa_options');
    delete_option('wwa_version');
    delete_option('wwa_log');
    delete_option('wwa_init');
    delete_option('wwa_credentials_migrated');
}

add_action('plugins_loaded', 'wwa_init_data');

function wwa_init_data(){
    $is_new_install = !get_option('wwa_init');
    if($is_new_install){
        // Init
        wwa_create_table();
        $site_domain = wp_parse_url(site_url(), PHP_URL_HOST);
        $wwa_init_options = array(
            'website_domain' => $site_domain === NULL ? "" : $site_domain,
            'remember_me' => 'false',
            'email_login' => 'false',
            'password_reset' => 'off',
            'after_user_registration' => 'none',
            'logging' => 'false',
            'terminology' => 'passkey',
            'allow_profile_test' => 'false',
        );
        if(!is_multisite()){
            $wwa_init_options['first_choice'] = 'true';
            $wwa_init_options['user_verification'] = 'false';
            $wwa_init_options['usernameless_login'] = 'false';
            $wwa_init_options['allow_authenticator_type'] = 'none';
            $wwa_init_options['show_authenticator_type'] = 'false';
            $wwa_init_options['ror_origins'] = '';
            $wwa_init_options['ror_origins_normalized'] = array();
            $wwa_init_options['conditional_create'] = 'off';
        }
        update_option('wwa_options', $wwa_init_options);
        include('wwa-version.php');
        update_option('wwa_version', $wwa_version);
        update_option('wwa_log', array());
        update_option('wwa_init', md5(date('Y-m-d H:i:s'))); // phpcs:ignore WordPress.DateTime.RestrictedFunctions.date_date
        add_action('wp_loaded', 'wwa_apply_rewrite_rules');
    }else{
        include('wwa-version.php');
        if(!get_option('wwa_version') || get_option('wwa_version')['version'] != $wwa_version['version']){
            update_option('wwa_version', $wwa_version);
            add_action('wp_loaded', 'wwa_apply_rewrite_rules');
        }
    }

    wwa_maybe_upgrade_credentials_schema();
    if(is_multisite()){
        wwa_migrate_network_options($is_new_install);
    }else{
        wwa_migrate_credentials_for_site();
    }
    wwa_init_new_options();
}

// Wrap WP-WebAuthn settings
function wwa_get_option($option_name){
    if(is_multisite() && in_array($option_name, WWA_NETWORK_OPTION_NAMES, true)){
        $val = get_site_option('wwa_network_options');
        if(is_array($val) && isset($val[$option_name])){
            return $val[$option_name];
        }
        return false;
    }

    $val = get_option('wwa_options');
    if(isset($val[$option_name])){
        return $val[$option_name];
    }else{
        return false;
    }
}

function wwa_update_option($option_name, $option_value){
    $normalized_ror = null;
    if($option_name === 'ror_origins'){
        $normalized_ror = wwa_sanitize_ror_origins($option_value);
        $option_value = implode("\n", $normalized_ror);
    }

    if(is_multisite() && in_array($option_name, WWA_NETWORK_OPTION_NAMES, true)){
        $options = get_site_option('wwa_network_options', array());
        $options[$option_name] = $option_value;
        if($option_name === 'ror_origins'){
            $options['ror_origins_normalized'] = $normalized_ror;
        }
        update_site_option('wwa_network_options', $options);
        return true;
    }

    $options = get_option('wwa_options');
    $options[$option_name] = $option_value;
    if($option_name === 'ror_origins'){
        $options['ror_origins_normalized'] = $normalized_ror;
    }
    update_option('wwa_options',$options);
    return true;
}

include('wwa-menus.php');
include('wwa-functions.php');
include('wwa-migrations.php');
include('wwa-credential-repository.php');
include('wwa-ajax.php');
include('wwa-shortcodes.php');

function wwa_admin_enqueue_conditional_create(){
    if(!current_user_can('read')){
        return;
    }
    $conditional_create_mode = wwa_get_effective_conditional_create_mode_for_user(get_current_user_id());
    if($conditional_create_mode === 'off'){
        return;
    }
    $version = get_option('wwa_version')['version'];
    wp_enqueue_script('wwa_webauthn_helpers', plugins_url('js/webauthn-helpers.js', __FILE__), array(), $version, true);
    wp_enqueue_script('wwa_admin_conditional_create', plugins_url('js/admin-conditional-create.js', __FILE__), array('wwa_webauthn_helpers'), $version, true);
    wp_localize_script('wwa_admin_conditional_create', 'wwa_conditional_create_vars', array(
        'ajax_url' => admin_url('admin-ajax.php'),
        '_ajax_nonce' => wp_create_nonce('wwa_ajax'),
        'conditional_create' => $conditional_create_mode
    ));
}
add_action('admin_enqueue_scripts', 'wwa_admin_enqueue_conditional_create');

register_activation_hook(__FILE__, 'wwa_apply_rewrite_rules');
register_deactivation_hook(__FILE__, 'wwa_deactivate');

function wwa_deactivate($network_wide){
    if(is_multisite() && $network_wide){
        $sites = get_sites(array('fields' => 'ids', 'number' => 0));
        foreach($sites as $blog_id){
            switch_to_blog($blog_id);
            flush_rewrite_rules();
            restore_current_blog();
        }
    }else{
        flush_rewrite_rules();
    }
}
