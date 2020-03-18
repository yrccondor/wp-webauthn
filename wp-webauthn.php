<?php
/*
Plugin Name: WP-WebAuthn
Plugin URI: https://flyhigher.top
Description: Description: WP-WebAuthn 使你可以通过 U2F 设备登录账户而无需输入密码。
Version: 1.0.0
Author: Axton
Author URI: https://axton.cc
License: GPLv3
*/
/* Copyright 2020 Axton
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version  of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
*/

register_activation_hook(__FILE__, 'wwa_init');

function wwa_init(){
    if(version_compare(get_bloginfo('version'), '4.4', '<')){
        deactivate_plugins(basename(__FILE__)); //disable
    }else{
        wwa_init_data();
    }
}

wwa_init_data();

function wwa_init_data(){
    if(!get_option('wwa_init')){
        // Init
        $wwa_init_options = array(
            'user_credentials' => "{}",
            'user_credentials_meta' => "{}",
            'user_id' => array(),
            'first_choice' => 'true',
            'webite_name' => get_bloginfo('name'),
            'webite_domain' => explode(":", explode("/", explode("//", site_url())[1])[0])[0],
            'user_verification' => 'false'
        );
        update_option('wwa_options', $wwa_init_options);
        include('version.php');
        update_option('wwa_version', $wwa_version);
        update_option('wwa_init', md5(date('Y-m-d H:i:s')));
    }else{
        include('version.php');
        if(!get_option('wwa_version') || get_option('wwa_version')['version'] != $wwa_version['version']){
            update_option('wwa_version', $wwa_version); //update version
        }
    }
}

// Wrap WP-WebAuthn settings
function wwa_get_option($option_name){
    return get_option("wwa_options")[$option_name];
}

function wwa_update_option($option_name, $option_value){
    $options = get_option("wwa_options");
    $options[$option_name] = $option_value;
    update_option('wwa_options',$options);
    return true;
}

include('wwa-menus.php');
include('wwa-functions.php');
include('wwa-ajax.php');
?>