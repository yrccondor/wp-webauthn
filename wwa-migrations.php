<?php

if (!defined('ABSPATH')) {
    exit;
}

function wwa_credentials_schema_target_version(): int {
    return 2;
}

function wwa_credentials_schema_option_name(): string {
    return 'wwa_credentials_schema_version';
}

function wwa_credentials_schema_warning_option_name(): string {
    return 'wwa_credentials_schema_warning';
}

function wwa_get_credentials_schema_version(): int {
    $version = is_multisite()
        ? get_site_option(wwa_credentials_schema_option_name(), 0)
        : get_option(wwa_credentials_schema_option_name(), 0);
    return intval($version);
}

function wwa_update_credentials_schema_version(int $version): void {
    if(is_multisite()){
        update_site_option(wwa_credentials_schema_option_name(), $version);
        return;
    }
    update_option(wwa_credentials_schema_option_name(), $version);
}

function wwa_get_credentials_schema_warning() {
    return is_multisite()
        ? get_site_option(wwa_credentials_schema_warning_option_name(), '')
        : get_option(wwa_credentials_schema_warning_option_name(), '');
}

function wwa_update_credentials_schema_warning(string $message): void {
    if(is_multisite()){
        update_site_option(wwa_credentials_schema_warning_option_name(), $message);
        return;
    }
    update_option(wwa_credentials_schema_warning_option_name(), $message);
}

function wwa_delete_credentials_schema_warning(): void {
    if(is_multisite()){
        delete_site_option(wwa_credentials_schema_warning_option_name());
        return;
    }
    delete_option(wwa_credentials_schema_warning_option_name());
}

function wwa_credentials_table_exists(): bool {
    global $wpdb;
    $table = $wpdb->wwa_credentials;
    return $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table))) === $table;
}

function wwa_credentials_column_exists(string $column): bool {
    global $wpdb;
    if(!wwa_credentials_table_exists()){
        return false;
    }
    $row = $wpdb->get_row($wpdb->prepare("SHOW COLUMNS FROM {$wpdb->wwa_credentials} LIKE %s", $column));
    return $row !== null;
}

function wwa_credentials_primary_columns(): array {
    global $wpdb;
    if(!wwa_credentials_table_exists()){
        return array();
    }
    $rows = $wpdb->get_results("SHOW KEYS FROM {$wpdb->wwa_credentials} WHERE Key_name = 'PRIMARY'");
    if(!is_array($rows)){
        return array();
    }
    usort($rows, function($a, $b){
        return intval($a->Seq_in_index) <=> intval($b->Seq_in_index);
    });
    return array_map(function($row){
        return $row->Column_name;
    }, $rows);
}

function wwa_credentials_index_is_unique(string $index_name): ?bool {
    global $wpdb;
    if(!wwa_credentials_table_exists()){
        return null;
    }
    $row = $wpdb->get_row($wpdb->prepare("SHOW INDEX FROM {$wpdb->wwa_credentials} WHERE Key_name = %s", $index_name));
    if($row === null){
        return null;
    }
    return intval($row->Non_unique) === 0;
}

function wwa_credentials_schema_failure(): void {
    $message = __('WP-WebAuthn could not finish updating passkey storage. Please try again or contact your site administrator.', 'wp-webauthn');
    wwa_update_credentials_schema_warning($message);
    wwa_add_log(wwa_generate_random_string(5), $message, true);
}

function wwa_run_credentials_schema_query(string $sql): bool {
    global $wpdb;
    $result = $wpdb->query($sql);
    if($result === false){
        wwa_credentials_schema_failure();
        return false;
    }
    return true;
}

function wwa_credentials_schema_is_ready(): bool {
    return wwa_credentials_table_exists()
        && wwa_credentials_column_exists('id')
        && wwa_credentials_column_exists('credential_hash')
        && wwa_credentials_primary_columns() === array('id')
        && wwa_credentials_index_is_unique('idx_credential_hash') === true;
}

function wwa_create_table() {
    global $wpdb;
    $table = $wpdb->wwa_credentials;
    $charset_collate = $wpdb->get_charset_collate();

    if(wwa_credentials_table_exists()){
        return;
    }

    $sql = "CREATE TABLE $table (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        credential_hash char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        credential_id text NOT NULL,
        user_id bigint(20) unsigned NOT NULL,
        registered_blog_id bigint(20) unsigned NOT NULL DEFAULT 1,
        credential_source longtext NOT NULL,
        user_handle varchar(255) NOT NULL,
        human_name text NOT NULL,
        authenticator_type varchar(50) NOT NULL,
        usernameless tinyint(1) NOT NULL DEFAULT 0,
        added datetime NOT NULL,
        last_used varchar(50) NOT NULL DEFAULT '-',
        PRIMARY KEY  (id),
        UNIQUE KEY idx_credential_hash (credential_hash),
        KEY idx_user_id (user_id),
        KEY idx_user_handle (user_handle),
        KEY idx_blog_user (registered_blog_id, user_id)
    ) $charset_collate;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);

    if(wwa_credentials_schema_is_ready()){
        wwa_update_credentials_schema_version(wwa_credentials_schema_target_version());
        wwa_delete_credentials_schema_warning();
    }
}

function wwa_cleanup_credential_hash_conflicts(): array {
    global $wpdb;

    $removed_duplicates = 0;
    $removed_unreadable = 0;
    $failed = false;
    $seen = array();

    $rows = $wpdb->get_results(
        "SELECT id, credential_id, credential_hash
         FROM {$wpdb->wwa_credentials}
         ORDER BY id ASC"
    );
    if(!is_array($rows)){
        wwa_credentials_schema_failure();
        return array('duplicates' => 0, 'unreadable' => 0, 'failed' => true);
    }

    foreach($rows as $row){
        $row_id = intval($row->id);
        $stored_id = is_string($row->credential_id) ? $row->credential_id : '';
        $raw_id = wwa_decode_base64_or_base64url($stored_id);
        $hash = is_string($row->credential_hash) ? $row->credential_hash : '';

        if($raw_id === ''){
            $deleted = $wpdb->delete($wpdb->wwa_credentials, array('id' => $row_id), array('%d'));
            if($deleted === false){
                wwa_credentials_schema_failure();
                $failed = true;
            }else{
                $removed_unreadable++;
            }
            continue;
        }

        $expected_hash = wwa_credential_hash($raw_id);
        if(isset($seen[$expected_hash])){
            $deleted = $wpdb->delete($wpdb->wwa_credentials, array('id' => $row_id), array('%d'));
            if($deleted === false){
                wwa_credentials_schema_failure();
                $failed = true;
            }else{
                $removed_duplicates++;
            }
            continue;
        }

        if($hash === '' || !hash_equals($expected_hash, $hash)){
            $updated = $wpdb->update(
                $wpdb->wwa_credentials,
                array(
                    'credential_hash' => $expected_hash,
                    'credential_id' => wwa_credential_storage_id($raw_id),
                ),
                array('id' => $row_id),
                array('%s', '%s'),
                array('%d')
            );
            if($updated === false){
                wwa_credentials_schema_failure();
                $failed = true;
                continue;
            }
        }

        $seen[$expected_hash] = true;
    }

    return array(
        'duplicates' => $removed_duplicates,
        'unreadable' => $removed_unreadable,
        'failed' => $failed,
    );
}

function wwa_ensure_credential_hash_index(): bool {
    global $wpdb;
    $is_unique = wwa_credentials_index_is_unique('idx_credential_hash');
    if($is_unique !== null){
        if($is_unique === true){
            return true;
        }
        if(!wwa_run_credentials_schema_query("ALTER TABLE {$wpdb->wwa_credentials} DROP INDEX idx_credential_hash")){
            return false;
        }
    }

    return wwa_run_credentials_schema_query("ALTER TABLE {$wpdb->wwa_credentials} ADD UNIQUE KEY idx_credential_hash (credential_hash)");
}

function wwa_upgrade_credentials_schema(): void {
    global $wpdb;

    if(!wwa_credentials_table_exists()){
        wwa_create_table();
        return;
    }

    $primary_columns = wwa_credentials_primary_columns();
    if($primary_columns !== array('id') && count($primary_columns) > 0){
        if(!wwa_run_credentials_schema_query("ALTER TABLE {$wpdb->wwa_credentials} DROP PRIMARY KEY")){
            return;
        }
    }

    if(!wwa_credentials_column_exists('id')){
        if(!wwa_run_credentials_schema_query("ALTER TABLE {$wpdb->wwa_credentials} ADD COLUMN id bigint(20) unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST")){
            return;
        }
    }elseif(wwa_credentials_primary_columns() !== array('id')){
        if(!wwa_run_credentials_schema_query("ALTER TABLE {$wpdb->wwa_credentials} ADD PRIMARY KEY (id)")){
            return;
        }
    }
    if(wwa_credentials_primary_columns() === array('id')){
        if(!wwa_run_credentials_schema_query("ALTER TABLE {$wpdb->wwa_credentials} MODIFY id bigint(20) unsigned NOT NULL AUTO_INCREMENT")){
            return;
        }
    }

    if(!wwa_credentials_column_exists('credential_hash')){
        if(!wwa_run_credentials_schema_query("ALTER TABLE {$wpdb->wwa_credentials} ADD COLUMN credential_hash char(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER id")){
            return;
        }
    }

    if(!wwa_run_credentials_schema_query("ALTER TABLE {$wpdb->wwa_credentials} MODIFY credential_id text NOT NULL")){
        return;
    }

    $cleanup = wwa_cleanup_credential_hash_conflicts();
    if($cleanup['failed']){
        return;
    }

    $missing_hashes = intval($wpdb->get_var(
        "SELECT COUNT(*) FROM {$wpdb->wwa_credentials}
         WHERE credential_hash IS NULL OR credential_hash = ''"
    ));
    if($missing_hashes > 0){
        wwa_credentials_schema_failure();
        return;
    }

    if(!wwa_run_credentials_schema_query("ALTER TABLE {$wpdb->wwa_credentials} MODIFY credential_hash char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL")){
        return;
    }

    if(!wwa_ensure_credential_hash_index()){
        $message = __('WP-WebAuthn updated passkey storage, but could not finish one final passkey storage safety check. Please try again or contact your site administrator.', 'wp-webauthn');
        wwa_update_credentials_schema_warning($message);
        wwa_add_log(wwa_generate_random_string(5), $message, true);
        return;
    }

    if($cleanup['duplicates'] > 0 || $cleanup['unreadable'] > 0){
        $message = __('WP-WebAuthn skipped duplicate or unreadable passkeys while updating storage. Existing valid passkeys were kept.', 'wp-webauthn');
        wwa_update_credentials_schema_warning($message);
        wwa_add_log(wwa_generate_random_string(5), $message, true);
    }else{
        wwa_delete_credentials_schema_warning();
    }

    if(wwa_credentials_schema_is_ready()){
        wwa_update_credentials_schema_version(wwa_credentials_schema_target_version());
    }else{
        wwa_credentials_schema_failure();
    }
}

function wwa_maybe_upgrade_credentials_schema(): void {
    if(wwa_get_credentials_schema_version() >= wwa_credentials_schema_target_version()){
        return;
    }
    wwa_upgrade_credentials_schema();
}

function wwa_migrate_credentials_for_site(){
    if(is_multisite()){
        return;
    }

    if(wwa_get_credentials_schema_version() < wwa_credentials_schema_target_version()){
        return;
    }

    if(get_option('wwa_credentials_migrated')){
        return;
    }

    global $wpdb;
    $migration_success = true;
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
        $message = __('WP-WebAuthn could not read one or more old passkeys while updating storage. The old data was left unchanged and the update will be retried.', 'wp-webauthn');
        wwa_update_credentials_schema_warning($message);
        wwa_add_log(wwa_generate_random_string(5), $message, true);
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

        $raw_credential_id = wwa_decode_base64_or_base64url($cred_id);
        if($raw_credential_id === ''){
            $message = __('WP-WebAuthn skipped an unreadable passkey while updating storage. Existing valid passkeys were kept.', 'wp-webauthn');
            wwa_update_credentials_schema_warning($message);
            wwa_add_log(wwa_generate_random_string(5), $message, true);
            continue;
        }
        $stored_credential_id = base64_encode($raw_credential_id);
        $credential_hash = wwa_credential_hash($raw_credential_id);

        $handle = $meta['user'];
        if(!isset($handle_to_login[$handle])){
            continue;
        }
        $wp_user = get_user_by('login', $handle_to_login[$handle]);
        if($wp_user === false){
            continue;
        }

        $existing_same_credential = $wpdb->get_var($wpdb->prepare(
            "SELECT 1 FROM {$wpdb->wwa_credentials}
             WHERE credential_hash = %s AND user_id = %d AND registered_blog_id = %d
             LIMIT 1",
            $credential_hash,
            $wp_user->ID,
            $blog_id
        ));
        if($existing_same_credential !== null){
            continue;
        }

        $existing_hash = $wpdb->get_var($wpdb->prepare(
            "SELECT 1 FROM {$wpdb->wwa_credentials} WHERE credential_hash = %s LIMIT 1",
            $credential_hash
        ));
        if($existing_hash !== null){
            $message = __('WP-WebAuthn skipped a duplicate passkey while updating storage. The existing passkey was kept.', 'wp-webauthn');
            wwa_add_log(wwa_generate_random_string(5), $message, true);
            continue;
        }

        $inserted = $wpdb->query($wpdb->prepare(
            "INSERT INTO {$wpdb->wwa_credentials}
            (credential_hash, credential_id, user_id, registered_blog_id, credential_source, user_handle, human_name, authenticator_type, usernameless, added, last_used)
            VALUES (%s, %s, %d, %d, %s, %s, %s, %s, %d, %s, %s)",
            $credential_hash,
            $stored_credential_id,
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
        if($inserted === false){
            $migration_success = false;
            $message = __('WP-WebAuthn could not move one or more old passkeys into the new storage. The old data was left unchanged and the update will be retried.', 'wp-webauthn');
            wwa_update_credentials_schema_warning($message);
            wwa_add_log(wwa_generate_random_string(5), $message, true);
        }
    }

    $site_users = get_users(array('blog_id' => $blog_id, 'fields' => 'ID'));
    foreach($site_users as $uid){
        if(get_user_option('webauthn_only', $uid) === 'true'){
            update_user_meta($uid, 'wwa_webauthn_only', 'true');
        }
    }

    if($migration_success){
        update_option('wwa_credentials_migrated', true);
    }
}

function wwa_migrate_network_options(bool $new_install = false){
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
        'ror_origins_normalized' => array(),
        'user_verification' => 'false',
        'usernameless_login' => 'false',
        'allow_authenticator_type' => 'none',
        'show_authenticator_type' => 'false',
        'allow_profile_test' => $new_install ? 'false' : 'true',
        'conditional_create' => 'off'
    );
    $network_options = array();
    foreach($network_defaults as $key => $default){
        if(is_array($options) && isset($options[$key])){
            $network_options[$key] = $key === 'conditional_create'
                ? wwa_normalize_conditional_create_mode($options[$key])
                : $options[$key];
        }else{
            $network_options[$key] = $default;
        }
    }
    $network_options['ror_origins_normalized'] = wwa_sanitize_ror_origins($network_options['ror_origins']);

    update_site_option('wwa_network_options', $network_options);
}

function wwa_credentials_schema_admin_notice(): void {
    $warning = wwa_get_credentials_schema_warning();
    if(!is_string($warning) || $warning === ''){
        return;
    }
    if(!current_user_can(is_multisite() ? 'manage_network_options' : 'manage_options')){
        return;
    }
    echo '<div class="notice notice-warning"><p>'.esc_html($warning).'</p></div>';
}

add_action('admin_notices', 'wwa_credentials_schema_admin_notice');
add_action('network_admin_notices', 'wwa_credentials_schema_admin_notice');
