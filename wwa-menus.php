<?php
/**
 * Add menus to the admin pannel
 */
//Add menu
function wwa_admin_menu(){
    add_options_page('WP-WebAuthn' , 'WP-WebAuthn', 'read', 'wwa_admin','wwa_display_main_menu');
}
function wwa_display_main_menu(){
    require_once('wwa-admin-content.php');
}
add_action('admin_menu', 'wwa_admin_menu');
?>