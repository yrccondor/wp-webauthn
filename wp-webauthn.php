<?php
/*
Plugin Name: WP-WebAuthn
Plugin URI: https://flyhigher.top
Description: WP-WebAuthn allows you to safely login to your WordPress site without password.
Version: 1.4.1
Author: Axton
Author URI: https://axton.cc
License: GPLv3
Text Domain: wp-webauthn
Domain Path: /languages
Network: true
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

function wwa_register_table() {
    global $wpdb;
    $wpdb->wwa_credentials = $wpdb->base_prefix . 'wwa_credentials';
}
wwa_register_table();
add_action('plugins_loaded', 'wwa_register_table', 0);

function wwa_create_table() {
    global $wpdb;
    $table = $wpdb->wwa_credentials;
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table (
        credential_id varchar(512) NOT NULL,
        user_id bigint(20) unsigned NOT NULL,
        registered_blog_id bigint(20) unsigned NOT NULL DEFAULT 1,
        credential_source longtext NOT NULL,
        user_handle varchar(255) NOT NULL,
        human_name text NOT NULL,
        authenticator_type varchar(50) NOT NULL,
        usernameless tinyint(1) NOT NULL DEFAULT 0,
        added datetime NOT NULL,
        last_used varchar(50) NOT NULL DEFAULT '-',
        PRIMARY KEY  (credential_id),
        KEY idx_user_id (user_id),
        KEY idx_user_handle (user_handle),
        KEY idx_blog_user (registered_blog_id, user_id)
    ) $charset_collate;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);
}

function wwa_migrate_credentials_for_site(){
    if(get_option('wwa_credentials_migrated')){
        return;
    }

    global $wpdb;
    $options = get_option('wwa_options');
    if(!is_array($options)){
        update_option('wwa_credentials_migrated', true);
        return;
    }

    $user_id_map = isset($options['user_id']) && is_array($options['user_id']) ? $options['user_id'] : array();
    $raw_creds = isset($options['user_credentials']) ? $options['user_credentials'] : '{}';
    $raw_meta = isset($options['user_credentials_meta']) ? $options['user_credentials_meta'] : '{}';

    $credentials = json_decode($raw_creds, true);
    $credentials_meta = json_decode($raw_meta, true);

    if(!is_array($credentials) || !is_array($credentials_meta)){
        update_option('wwa_credentials_migrated', true);
        return;
    }

    foreach($user_id_map as $user_login => $user_handle){
        $wp_user = get_user_by('login', $user_login);
        if($wp_user === false){
            continue;
        }
        $existing = get_user_meta($wp_user->ID, 'wwa_user_handle', true);
        if(!$existing){
            update_user_meta($wp_user->ID, 'wwa_user_handle', $user_handle);
        }
    }

    $handle_to_login = array();
    foreach($user_id_map as $user_login => $user_handle){
        $handle_to_login[$user_handle] = $user_login;
    }

    $blog_id = get_current_blog_id();
    foreach($credentials_meta as $cred_id => $meta){
        if(!isset($meta['user']) || !isset($credentials[$cred_id])){
            continue;
        }

        $handle = $meta['user'];
        if(!isset($handle_to_login[$handle])){
            continue;
        }
        $wp_user = get_user_by('login', $handle_to_login[$handle]);
        if($wp_user === false){
            continue;
        }

        $wpdb->query($wpdb->prepare(
            "INSERT IGNORE INTO {$wpdb->wwa_credentials}
            (credential_id, user_id, registered_blog_id, credential_source, user_handle, human_name, authenticator_type, usernameless, added, last_used)
            VALUES (%s, %d, %d, %s, %s, %s, %s, %d, %s, %s)",
            $cred_id,
            $wp_user->ID,
            $blog_id,
            wp_json_encode($credentials[$cred_id]),
            $handle,
            isset($meta['human_name']) ? $meta['human_name'] : '',
            isset($meta['authenticator_type']) ? $meta['authenticator_type'] : 'none',
            !empty($meta['usernameless']) ? 1 : 0,
            isset($meta['added']) ? $meta['added'] : current_time('mysql'),
            isset($meta['last_used']) ? $meta['last_used'] : '-'
        ));
    }

    $site_users = get_users(array('blog_id' => $blog_id, 'fields' => 'ID'));
    foreach($site_users as $uid){
        if(get_user_option('webauthn_only', $uid) === 'true'){
            update_user_meta($uid, 'wwa_webauthn_only', 'true');
        }
    }

    update_option('wwa_credentials_migrated', true);
}

function wwa_migrate_network_options(){
    if(!is_multisite() || get_site_option('wwa_network_options') !== false){
        return;
    }

    $main_site_id = get_main_site_id();
    switch_to_blog($main_site_id);
    $options = get_option('wwa_options');
    restore_current_blog();

    $network_defaults = array(
        'first_choice' => 'true',
        'ror_origins' => '',
        'user_verification' => 'false',
        'usernameless_login' => 'false',
        'allow_authenticator_type' => 'none',
        'show_authenticator_type' => 'false'
    );
    $network_options = array();
    foreach($network_defaults as $key => $default){
        if(is_array($options) && isset($options[$key])){
            $network_options[$key] = $options[$key];
        }else{
            $network_options[$key] = $default;
        }
    }

    update_site_option('wwa_network_options', $network_options);
}

register_activation_hook(__FILE__, 'wwa_init');
register_uninstall_hook(__FILE__, 'wwa_uninstall');

function wwa_init(){
    if(version_compare(get_bloginfo('version'), '5.0', '<')){
        deactivate_plugins(basename(__FILE__));
        return;
    }
    wwa_create_table();
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
        delete_site_option('wwa_all_sites_migrated');
    }else{
        wwa_uninstall_site();
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
    if(!get_option('wwa_init')){
        // Init
        wwa_create_table();
        $site_domain = wp_parse_url(site_url(), PHP_URL_HOST);
        $wwa_init_options = array(
            'website_name' => get_bloginfo('name'),
            'website_domain' => $site_domain === NULL ? "" : $site_domain,
            'remember_me' => 'false',
            'email_login' => 'false',
            'password_reset' => 'off',
            'after_user_registration' => 'none',
            'logging' => 'false',
            'terminology' => 'passkey',
        );
        if(!is_multisite()){
            $wwa_init_options['first_choice'] = 'true';
            $wwa_init_options['user_verification'] = 'false';
            $wwa_init_options['usernameless_login'] = 'false';
            $wwa_init_options['allow_authenticator_type'] = 'none';
            $wwa_init_options['show_authenticator_type'] = 'false';
            $wwa_init_options['ror_origins'] = '';
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
            wwa_create_table();
            wwa_migrate_credentials_for_site();

            if(is_multisite() && !get_site_option('wwa_all_sites_migrated')){
                $all_sites = get_sites(array('fields' => 'ids', 'number' => 0));
                foreach($all_sites as $site_id){
                    if(intval($site_id) === get_current_blog_id()){
                        continue;
                    }
                    switch_to_blog($site_id);
                    if(get_option('wwa_init')){
                        wwa_migrate_credentials_for_site();
                        update_option('wwa_version', $wwa_version);
                    }
                    restore_current_blog();
                }
                update_site_option('wwa_all_sites_migrated', true);
            }

            update_option('wwa_version', $wwa_version);
            add_action('wp_loaded', 'wwa_apply_rewrite_rules');
        }
    }

    if(is_multisite()){
        wwa_migrate_network_options();
    }
}

// Wrap WP-WebAuthn settings
function wwa_get_option($option_name){
    $network_options = array(
        'first_choice', 'ror_origins', 'user_verification',
        'usernameless_login', 'allow_authenticator_type', 'show_authenticator_type'
    );

    if(is_multisite() && in_array($option_name, $network_options, true)){
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
    $network_options = array(
        'first_choice', 'ror_origins', 'user_verification',
        'usernameless_login', 'allow_authenticator_type', 'show_authenticator_type'
    );

    if(is_multisite() && in_array($option_name, $network_options, true)){
        $options = get_site_option('wwa_network_options', array());
        $options[$option_name] = $option_value;
        update_site_option('wwa_network_options', $options);
        return true;
    }

    $options = get_option('wwa_options');
    $options[$option_name] = $option_value;
    update_option('wwa_options',$options);
    return true;
}

include('wwa-menus.php');
include('wwa-functions.php');
include('wwa-ajax.php');
include('wwa-shortcodes.php');

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
