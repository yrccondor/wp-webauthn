<?php
if (!defined('ABSPATH')) {
    exit;
}

require_once('wp-webauthn-vendor/autoload.php');
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\AppleAttestationStatementSupport;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\CompoundAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Signal\CurrentUserDetails;
use Webauthn\Signal\UnknownCredential;
use Webauthn\CeremonyStep\TopOriginValidator;
use Cose\Algorithm\Manager as CoseAlgorithmManager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;

// WordPress transient adapter
function wwa_set_temp_val($name, $value, $client_id){
    return set_transient('wwa_'.$name.$client_id, serialize($value), 90);
}

function wwa_get_temp_val($name, $client_id){
    $val = get_transient('wwa_'.$name.$client_id);
    if($val === false || !is_string($val)){
        return $val;
    }

    $unserialized = @unserialize($val, array('allowed_classes' => false));
    if($unserialized !== false || $val === serialize(false)){
        return $unserialized;
    }
    return $val;
}

function wwa_delete_temp_val($name, $client_id){
    return delete_transient('wwa_'.$name.$client_id);
}

function wwa_get_auth_browser_binding(bool $issue = false): string {
    $secure = wwa_check_ssl();
    $cookie_hash = defined('COOKIEHASH') ? COOKIEHASH : md5(site_url());
    $cookie_name = ($secure ? '__Host-' : '').'wwa_auth_binding_'.$cookie_hash;
    $token = isset($_COOKIE[$cookie_name]) && is_string($_COOKIE[$cookie_name])
        ? wp_unslash($_COOKIE[$cookie_name])
        : '';

    if(!preg_match('/^[a-f0-9]{64}$/', $token)){
        if(!$issue){
            return '';
        }
        $token = bin2hex(random_bytes(32));
    }

    if($issue){
        $cookie_set = setcookie($cookie_name, $token, array(
            'expires' => 0,
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Strict',
        ));
        if(!$cookie_set){
            return '';
        }
        $_COOKIE[$cookie_name] = $token;
    }

    return hash_hmac('sha256', $token, wp_salt('auth'));
}

function wwa_auth_request_is_same_origin(): bool {
    if(isset($_SERVER['HTTP_ORIGIN'])){
        $request_origin = is_string($_SERVER['HTTP_ORIGIN'])
            ? wwa_normalize_origin(wp_unslash($_SERVER['HTTP_ORIGIN']))
            : '';
        $current_origin = wwa_get_current_site_origin();
        if($request_origin === '' || $current_origin === '' || !hash_equals($current_origin, $request_origin)){
            return false;
        }
    }

    return !isset($_SERVER['HTTP_SEC_FETCH_SITE'])
        || (is_string($_SERVER['HTTP_SEC_FETCH_SITE'])
            && strtolower(trim($_SERVER['HTTP_SEC_FETCH_SITE'])) === 'same-origin');
}

function wwa_auth_state_matches_current_request($state): bool {
    if(!is_array($state)){
        return false;
    }

    foreach(array(
        'pkcco_auth', 'auth_type', 'user_exist', 'user_name_auth',
        'usernameless_auth', 'user_auth', 'browser_binding', 'blog_id', 'expires_at'
    ) as $key){
        if(!array_key_exists($key, $state)){
            return false;
        }
    }

    if(!is_string($state['pkcco_auth']) || $state['pkcco_auth'] === ''
        || !is_string($state['auth_type'])
        || !is_bool($state['user_exist'])
        || !is_bool($state['usernameless_auth'])
        || (!is_string($state['user_name_auth']) && $state['user_name_auth'] !== null)
        || (!is_string($state['user_auth']) && $state['user_auth'] !== null)
        || !is_string($state['browser_binding'])
        || intval($state['blog_id']) !== get_current_blog_id()
        || intval($state['expires_at']) < time()
    ){
        return false;
    }

    $current_binding = wwa_get_auth_browser_binding();
    return $current_binding !== '' && hash_equals($state['browser_binding'], $current_binding);
}

function wwa_consume_auth_state(string $client_id) {
    global $wpdb;

    $lock_name = 'wwa_auth_consume_lock_'.$client_id;
    $lock_acquired = $wpdb->query($wpdb->prepare(
        "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, '1', 'no')",
        $lock_name
    ));
    if($lock_acquired !== 1){
        return false;
    }

    $release_lock = true;
    try{
        $state = wwa_get_temp_val('auth', $client_id);
        if(!wwa_auth_state_matches_current_request($state)){
            return false;
        }
        if(!wwa_delete_temp_val('auth', $client_id)){
            // Fail closed if the state could not be removed atomically under
            // the lock. Keeping the lock prevents a later replay attempt.
            $release_lock = false;
            return false;
        }
        return $state;
    }finally{
        if($release_lock){
            $wpdb->delete($wpdb->options, array('option_name' => $lock_name), array('%s'));
        }
    }
}

// Destroy all transients
function wwa_destroy_temp_val($client_id){
    wwa_delete_temp_val('pkcco', $client_id);
    wwa_delete_temp_val('pkcco_conditional', $client_id);
    wwa_delete_temp_val('bind_config', $client_id);
    wwa_delete_temp_val('bind_config_conditional', $client_id);
    wwa_delete_temp_val('auth', $client_id);
}

// Destroy all transients before wp_die
function wwa_wp_die($message = '', $client_id = false){
    if($client_id !== false){
        wwa_destroy_temp_val($client_id);
    }
    wp_die(esc_html($message));
}

function wwa_auth_json_success($client_id = false, array $data = array(), int $status_code = 200){
    if($client_id !== false){
        wwa_delete_temp_val('auth', $client_id);
    }
    wp_send_json(array_merge(array('success' => true), $data), $status_code);
}

function wwa_auth_json_failure($message = '', $client_id = false, array $data = array(), int $status_code = 400){
    if($client_id !== false){
        wwa_delete_temp_val('auth', $client_id);
    }
    wp_send_json(array_merge(array(
        'success' => false,
        'message' => $message,
    ), $data), $status_code);
}

function wwa_normalize_login_redirect($redirect_to = '', string $fallback = ''): string {
    $fallback = $fallback === '' ? admin_url() : wp_validate_redirect($fallback, admin_url());
    $redirect_to = is_string($redirect_to) ? trim($redirect_to) : '';
    if($redirect_to === ''){
        return $fallback;
    }
    return wp_validate_redirect($redirect_to, $fallback);
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
    if(wwa_get_option('allow_profile_test') === false){
        wwa_update_option('allow_profile_test', 'true');
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
    if(wwa_get_option('ror_origins_normalized') === false){
        wwa_update_option('ror_origins_normalized', wwa_sanitize_ror_origins(wwa_get_option('ror_origins')));
    }
    if(wwa_get_option('conditional_create') === false){
        wwa_update_option('conditional_create', 'off');
    }
    if(is_multisite() && wwa_get_option('credential_scope') === false){
        wwa_update_option('credential_scope', 'network_accessible');
    }
}

function wwa_normalize_conditional_create_mode($mode): string {
    $mode = is_string($mode) ? sanitize_text_field($mode) : '';
    return in_array($mode, array('no-credentials', 'unregistered-device', 'off'), true) ? $mode : 'off';
}

function wwa_get_conditional_create_mode(): string {
    return wwa_normalize_conditional_create_mode(wwa_get_option('conditional_create'));
}

function wwa_is_conditional_create_enabled(?string $mode = null): bool {
    if(($mode ?? wwa_get_conditional_create_mode()) === 'off'){
        return false;
    }
    $allowed_type = wwa_get_option('allow_authenticator_type');
    return $allowed_type === false || $allowed_type === 'none';
}

function wwa_normalize_credential_scope($scope): string {
    $scope = is_string($scope) ? sanitize_text_field($scope) : '';
    return in_array($scope, array('network_accessible', 'site'), true) ? $scope : 'network_accessible';
}

function wwa_get_credential_scope(): string {
    if(!is_multisite()){
        return 'site';
    }
    return wwa_normalize_credential_scope(wwa_get_option('credential_scope'));
}

function wwa_normalize_blog_id_list($blog_ids): array {
    if(!is_array($blog_ids)){
        return array();
    }

    $normalized = array();
    foreach($blog_ids as $blog_id){
        $blog_id = intval($blog_id);
        if($blog_id > 0){
            $normalized[$blog_id] = $blog_id;
        }
    }
    return array_values($normalized);
}

function wwa_blog_is_active(int $blog_id): bool {
    if($blog_id <= 0){
        return false;
    }
    if(!is_multisite()){
        return $blog_id === get_current_blog_id();
    }

    $site = get_site($blog_id);
    if(!$site){
        return false;
    }

    return empty($site->deleted) && empty($site->spam) && empty($site->archived);
}

function wwa_user_can_access_blog(int $user_id, ?int $blog_id = null): bool {
    $blog_id = $blog_id === null ? get_current_blog_id() : $blog_id;
    if($user_id <= 0 || !wwa_blog_is_active($blog_id)){
        return false;
    }
    if(!is_multisite()){
        return $blog_id === get_current_blog_id() && get_userdata($user_id) !== false;
    }
    if(is_super_admin($user_id)){
        return true;
    }
    return is_user_member_of_blog($user_id, $blog_id);
}

function wwa_get_credential_scope_blog_ids_for_user(int $user_id): array {
    global $wpdb;

    if(!wwa_user_can_access_blog($user_id, get_current_blog_id())){
        return array();
    }

    if(wwa_get_credential_scope() === 'site'){
        return array(get_current_blog_id());
    }

    $credential_blog_ids = $wpdb->get_col($wpdb->prepare(
        "SELECT DISTINCT registered_blog_id FROM {$wpdb->wwa_credentials} WHERE user_id = %d",
        $user_id
    ));
    $candidate_ids = wwa_normalize_blog_id_list(array_merge(
        array(get_current_blog_id()),
        is_array($credential_blog_ids) ? $credential_blog_ids : array()
    ));

    if(is_super_admin($user_id)){
        return wwa_normalize_blog_id_list(get_sites(array(
            'fields' => 'ids',
            'number' => 0,
            'site__in' => $candidate_ids,
            'deleted' => 0,
            'spam' => 0,
            'archived' => 0,
        )));
    }

    $accessible_ids = array();
    foreach($candidate_ids as $candidate_id){
        if($candidate_id === get_current_blog_id() || wwa_user_can_access_blog($user_id, $candidate_id)){
            $accessible_ids[] = $candidate_id;
        }
    }
    return $accessible_ids;
}

function wwa_get_effective_conditional_create_mode_for_user(int $user_id): string {
    $mode = wwa_get_conditional_create_mode();
    if(!wwa_is_conditional_create_enabled($mode) || $user_id <= 0
        || !wwa_user_can_access_blog($user_id, get_current_blog_id())
    ){
        return 'off';
    }
    if($mode === 'no-credentials'){
        $blog_ids = wwa_get_credential_scope_blog_ids_for_user($user_id);
        if(count($blog_ids) === 0){
            return 'off';
        }
        $credentialRecordRepository = new CredentialRecordRepository();
        return $credentialRecordRepository->userHasCredentials($user_id, $blog_ids) ? 'off' : $mode;
    }
    return $mode;
}

function wwa_user_has_usable_credentials(int $user_id): bool {
    $blog_ids = wwa_get_credential_scope_blog_ids_for_user($user_id);
    if(count($blog_ids) === 0){
        return false;
    }

    $credentialRecordRepository = new CredentialRecordRepository();
    return $credentialRecordRepository->userHasCredentials($user_id, $blog_ids);
}

function wwa_base64url_encode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function wwa_decode_base64_or_base64url(string $data): string {
    $data = trim($data);
    if($data === ''){
        return '';
    }
    $data = strtr($data, '-_', '+/');
    $pad = strlen($data) % 4;
    if($pad !== 0){
        if($pad === 1){
            return '';
        }
        $data .= str_repeat('=', 4 - $pad);
    }
    $decoded = base64_decode($data, true);
    return is_string($decoded) ? $decoded : '';
}

function wwa_credential_hash(string $raw_credential_id): string {
    return hash('sha256', $raw_credential_id);
}

function wwa_credential_hash_from_encoded_id(string $encoded_credential_id): string {
    $raw_credential_id = wwa_decode_base64_or_base64url($encoded_credential_id);
    return $raw_credential_id === '' ? '' : wwa_credential_hash($raw_credential_id);
}

function wwa_credential_storage_id(string $raw_credential_id): string {
    return base64_encode($raw_credential_id);
}

function wwa_credential_storage_id_to_urlsafe(string $stored_credential_id): string {
    $raw_credential_id = wwa_decode_base64_or_base64url($stored_credential_id);
    return $raw_credential_id === '' ? '' : wwa_base64url_encode($raw_credential_id);
}

function wwa_decode_client_credential_payload($encoded_payload): ?array {
    if(!is_string($encoded_payload)){
        return null;
    }

    $encoded_payload = sanitize_text_field(wp_unslash($encoded_payload));
    if($encoded_payload === ''){
        return null;
    }

    $json = base64_decode($encoded_payload, true);
    if(!is_string($json) || $json === ''){
        return null;
    }

    $data = json_decode($json, true);
    if(!is_array($data) || empty($data['rawId']) || !is_string($data['rawId'])){
        return null;
    }

    $raw_id = wwa_decode_base64_or_base64url($data['rawId']);
    if($raw_id === ''){
        return null;
    }

    return array(
        'json' => $json,
        'data' => $data,
        'raw_id' => $raw_id,
    );
}

function wwa_is_loopback_host(string $host): bool {
    $host = strtolower($host);
    return $host === 'localhost' || $host === '127.0.0.1';
}

function wwa_get_public_suffixes(): array {
    $suffixes = array_fill_keys(array(
        'ac.uk', 'co.uk', 'gov.uk', 'ltd.uk', 'me.uk', 'net.uk', 'nhs.uk', 'org.uk', 'plc.uk', 'police.uk', 'sch.uk',
        'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
        'ac.jp', 'ad.jp', 'co.jp', 'ed.jp', 'go.jp', 'gr.jp', 'lg.jp', 'ne.jp', 'or.jp',
        'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
        'com.hk', 'net.hk', 'org.hk', 'edu.hk', 'gov.hk', 'idv.hk',
        'com.tw', 'net.tw', 'org.tw', 'edu.tw', 'gov.tw', 'idv.tw',
        'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
        'com.mx', 'org.mx', 'gob.mx', 'edu.mx', 'net.mx',
        'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr',
        'co.nz', 'net.nz', 'org.nz', 'ac.nz', 'govt.nz', 'school.nz',
        'co.kr', 'ne.kr', 'or.kr', 'go.kr', 'ac.kr', 're.kr',
        'co.in', 'firm.in', 'net.in', 'org.in', 'gen.in', 'ind.in',
        'co.za', 'net.za', 'org.za', 'gov.za', 'ac.za',
        'co.com', 'github.io', 'pages.dev', 'workers.dev', 'cloudflarepages.com', 'vercel.app', 'netlify.app',
        'herokuapp.com', 'appspot.com', 'firebaseapp.com', 'web.app', 'azurewebsites.net', 'cloudapp.net',
        'cloudfront.net', 's3.amazonaws.com'
    ), true);

    $filtered = apply_filters('wwa_public_suffixes', $suffixes);
    if(!is_array($filtered)){
        return $suffixes;
    }

    $normalized = array();
    foreach($filtered as $key => $value){
        $suffix = is_string($key) ? $key : $value;
        if(is_string($suffix)){
            $suffix = trim(strtolower($suffix), '.');
            if($suffix !== ''){
                $normalized[$suffix] = true;
            }
        }
    }
    return $normalized;
}

function wwa_is_public_suffix_host(string $host): bool {
    $host = trim(strtolower($host), '.');
    if($host === '' || wwa_is_loopback_host($host) || filter_var($host, FILTER_VALIDATE_IP)){
        return false;
    }

    $labels = explode('.', $host);
    if(count($labels) < 2){
        return true;
    }

    $suffixes = wwa_get_public_suffixes();
    if(isset($suffixes[$host])){
        return true;
    }

    $common_country_code_second_level_labels = array_fill_keys(array(
        'ac', 'co', 'com', 'edu', 'gov', 'gob', 'go', 'mil', 'ne', 'net', 'nom', 'or', 'org', 'sch'
    ), true);
    if(count($labels) === 2 && strlen($labels[1]) === 2 && isset($common_country_code_second_level_labels[$labels[0]])){
        return true;
    }

    return false;
}

function wwa_normalize_rp_id($value): string {
    $value = trim(strtolower(sanitize_text_field((string) $value)));
    if($value === ''){
        return '';
    }

    if(strpos($value, '://') !== false){
        $parsed = wp_parse_url($value);
    }else{
        $parsed = wp_parse_url('https://'.$value);
    }

    if(!is_array($parsed) || empty($parsed['host'])){
        return '';
    }
    if(isset($parsed['path']) && $parsed['path'] !== '' && $parsed['path'] !== '/'){
        return '';
    }
    if(isset($parsed['query']) || isset($parsed['fragment']) || isset($parsed['user']) || isset($parsed['pass'])){
        return '';
    }

    $host = trim(strtolower($parsed['host']), '.');
    if($host === '' || strpos($host, '*') !== false || preg_match('/\s/', $host)){
        return '';
    }
    if(wwa_is_loopback_host($host)){
        return $host;
    }
    if(filter_var($host, FILTER_VALIDATE_IP)){
        return '';
    }
    if(filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false || strpos($host, '.') === false || wwa_is_public_suffix_host($host)){
        return '';
    }
    return $host;
}

function wwa_normalize_origin($value): string {
    $value = trim(sanitize_text_field((string) $value));
    if($value === ''){
        return '';
    }

    $parsed = wp_parse_url($value);
    if(!is_array($parsed) || empty($parsed['scheme']) || empty($parsed['host'])){
        return '';
    }
    if(isset($parsed['path']) && $parsed['path'] !== '' && $parsed['path'] !== '/'){
        return '';
    }
    if(isset($parsed['query']) || isset($parsed['fragment']) || isset($parsed['user']) || isset($parsed['pass'])){
        return '';
    }

    $scheme = strtolower($parsed['scheme']);
    $host = trim(strtolower($parsed['host']), '.');
    if($host === '' || strpos($host, '*') !== false || preg_match('/\s/', $host)){
        return '';
    }
    if($scheme !== 'https' && !($scheme === 'http' && wwa_is_loopback_host($host))){
        return '';
    }
    if(!wwa_is_loopback_host($host) && !filter_var($host, FILTER_VALIDATE_IP) && (filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false || strpos($host, '.') === false || wwa_is_public_suffix_host($host))){
        return '';
    }

    $origin = $scheme.'://'.$host;
    if(isset($parsed['port'])){
        $port = intval($parsed['port']);
        if($port <= 0 || $port > 65535){
            return '';
        }
        if(!(($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80))){
            $origin .= ':'.$port;
        }
    }
    return $origin;
}

function wwa_sanitize_ror_origins($raw): array {
    $lines = is_array($raw) ? $raw : explode("\n", (string) $raw);
    $origins = array();
    foreach($lines as $line){
        $origin = wwa_normalize_origin($line);
        if($origin !== ''){
            $origins[$origin] = true;
        }
    }
    return array_keys($origins);
}

function wwa_get_current_site_origin(): string {
    $parsed = wp_parse_url(site_url());
    if(!is_array($parsed) || empty($parsed['scheme']) || empty($parsed['host'])){
        return '';
    }
    $scheme = strtolower($parsed['scheme']);
    $origin = $scheme.'://'.strtolower($parsed['host']);
    if(isset($parsed['port'])){
        $port = intval($parsed['port']);
        if(!(($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80))){
            $origin .= ':'.$port;
        }
    }
    return wwa_normalize_origin($origin);
}

function wwa_get_current_site_host(): string {
    $parsed = wp_parse_url(site_url());
    if(is_array($parsed) && !empty($parsed['host'])){
        return strtolower($parsed['host']);
    }
    return wwa_get_rp_id();
}

function wwa_get_rp_id(): string {
    return wwa_normalize_rp_id(wwa_get_option('website_domain'));
}

function wwa_get_rp_entity(?string $rp_id = null): PublicKeyCredentialRpEntity {
    return PublicKeyCredentialRpEntity::create('', $rp_id ?? wwa_get_rp_id());
}

function wwa_get_or_create_user_handle($user_info, ?string $res_id = null): string {
    $user_key = get_user_meta($user_info->ID, 'wwa_user_handle', true);
    if($user_key){
        return $user_key;
    }

    $user_id_map = wwa_get_option('user_id');
    if(is_array($user_id_map) && isset($user_id_map[$user_info->user_login])){
        $user_key = $user_id_map[$user_info->user_login];
        update_user_meta($user_info->ID, 'wwa_user_handle', $user_key);
        return $user_key;
    }

    if($res_id !== null){
        wwa_add_log($res_id, 'User not initialized, initialize');
    }
    $user_key = hash('sha256', $user_info->user_login.'-'.$user_info->display_name.'-'.wwa_generate_random_string(10));
    update_user_meta($user_info->ID, 'wwa_user_handle', $user_key);
    return $user_key;
}

function wwa_get_user_entity($user_info, ?string $user_key = null): PublicKeyCredentialUserEntity {
    return PublicKeyCredentialUserEntity::create(
        $user_info->user_login,
        $user_key ?? wwa_get_or_create_user_handle($user_info),
        $user_info->display_name
    );
}

function wwa_get_public_key_hints(string $authenticator_type): array {
    if($authenticator_type === 'platform'){
        return array('client-device');
    }
    if($authenticator_type === 'cross-platform'){
        return array('security-key', 'hybrid');
    }
    return array();
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

function wwa_get_log_limit(): int {
    return 1000;
}

function wwa_normalize_log_entries($log): array {
    if(!is_array($log)){
        return array();
    }

    $limit = wwa_get_log_limit();
    if(count($log) > $limit){
        return array_slice($log, -$limit);
    }
    return $log;
}

function wwa_get_log_entries(bool $persist_trim = false): array {
    $raw_log = get_option('wwa_log');
    $log = wwa_normalize_log_entries($raw_log);
    if($persist_trim && $raw_log !== false && $raw_log !== $log){
        update_option('wwa_log', $log);
    }
    return $log;
}

// Add log
function wwa_add_log($id, $content = '', $init = false){
    if(wwa_get_option('logging') !== 'true' && !$init){
        return;
    }
    $log = wwa_get_log_entries();
    $log[] = '['.current_time('mysql').']['.$id.'] '.wp_strip_all_tags($content);
    $log = wwa_normalize_log_entries($log);
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

function wwa_cleanup_site_credentials($site){
    if(!is_multisite()){
        return;
    }

    if(is_object($site)){
        $blog_id = isset($site->blog_id) ? intval($site->blog_id) : intval($site->id ?? 0);
    }else{
        $blog_id = intval($site);
    }
    if($blog_id <= 0){
        return;
    }

    global $wpdb;
    $wpdb->delete($wpdb->wwa_credentials, array('registered_blog_id' => $blog_id), array('%d'));
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
add_action('wp_uninitialize_site', 'wwa_cleanup_site_credentials', 10, 1);
add_action('delete_blog', 'wwa_cleanup_site_credentials', 10, 1);

// Add CSS and JS in login page
function wwa_login_js(){
    $wwa_not_allowed = false;
    if(!function_exists('mb_substr') || !wwa_check_ssl() && (wp_parse_url(site_url(), PHP_URL_HOST) !== 'localhost' && wp_parse_url(site_url(), PHP_URL_HOST) !== '127.0.0.1')){
        $wwa_not_allowed = true;
    }
    wp_enqueue_script('wwa_webauthn_helpers', plugins_url('js/webauthn-helpers.js', __FILE__), array(), get_option('wwa_version')['version'], true);
    wp_enqueue_script('wwa_login', plugins_url('js/login.js', __FILE__), array('wwa_webauthn_helpers'), get_option('wwa_version')['version'], true);
    $first_choice = wwa_get_option('first_choice');
    wp_localize_script('wwa_login', 'wwa_login_php_vars', array(
        'ajax_url' => admin_url('admin-ajax.php'),
        'admin_url' => admin_url(),
        'usernameless' => (wwa_get_option('usernameless_login') === false ? 'false' : wwa_get_option('usernameless_login')),
        'remember_me' => (wwa_get_option('remember_me') === false ? 'false' : wwa_get_option('remember_me')),
        'email_login' => (wwa_get_option('email_login') === false ? 'false' : wwa_get_option('email_login')),
        'allow_authenticator_type' => (wwa_get_option('allow_authenticator_type') === false ? "none" : wwa_get_option('allow_authenticator_type')),
        'webauthn_only' => ($first_choice === 'webauthn' && !$wwa_not_allowed) ? 'true' : 'false',
        'first_choice' => ($first_choice === false ? 'true' : $first_choice),
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
    if(!function_exists('mb_substr') || !wwa_check_ssl() && (wp_parse_url(site_url(), PHP_URL_HOST) !== 'localhost' && wp_parse_url(site_url(), PHP_URL_HOST) !== '127.0.0.1')){
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
        if(!wwa_user_has_usable_credentials(intval($user_info->ID))){ ?>
            <div class="notice notice-warning">
                <?php
                $wwa_scope_label = esc_html($first_choice === 'webauthn' ? __('the site', 'wp-webauthn') : __('your account', 'wp-webauthn'));
                $wwa_cred_label = esc_html(wwa_get_option('terminology') === 'webauthn' ? __('WebAuthn authenticator', 'wp-webauthn') : __('passkey', 'wp-webauthn'));
                /* translators: %1$s: 'the site' or 'your account', %2$s: 'WebAuthn authenticator' or 'passkey', %3$s: admin profile url */
                ?>
                <p><?php echo wp_kses(sprintf(__('Logging in with password has been disabled for %1$s but you haven\'t register any %2$s on the current site yet. You may unable to login again once you log out. <a href="%3$s#wwa-webauthn-start">Register</a>', 'wp-webauthn'), $wwa_scope_label, $wwa_cred_label, esc_url(admin_url('profile.php'))), array('a' => array('href' => array())));?></p>
                <?php if(is_multisite() && !is_subdomain_install() && wwa_get_credential_scope() === 'network_accessible'){
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

        if(!wwa_user_has_usable_credentials(intval($other_user->ID))){ ?>
            <div class="notice notice-warning">
                <?php
                $wwa_scope_label = esc_html($first_choice === 'webauthn' ? __('the site', 'wp-webauthn') : __('this account', 'wp-webauthn'));
                $wwa_cred_label = esc_html(wwa_get_option('terminology') === 'webauthn' ? __('WebAuthn authenticator', 'wp-webauthn') : __('passkey', 'wp-webauthn'));
                /* translators: %1$s: 'the site' or 'this account', %2$s: 'WebAuthn authenticator' or 'passkey' */
                ?>
                <p><?php echo wp_kses(sprintf(__('Logging in with password has been disabled for %1$s but <strong>this account</strong> haven\'t register any %2$s on the current site yet. This user may unable to login.', 'wp-webauthn'), $wwa_scope_label, $wwa_cred_label), array('strong' => array()));?></p>
                <?php if(is_multisite() && !is_subdomain_install() && wwa_get_credential_scope() === 'network_accessible'){
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
    $normalized = wwa_get_option('ror_origins_normalized');
    if(is_array($normalized)){
        return array_values(array_filter($normalized, function($origin){
            return is_string($origin) && $origin !== '';
        }));
    }

    $normalized = wwa_sanitize_ror_origins(wwa_get_option('ror_origins'));
    wwa_update_option('ror_origins_normalized', $normalized);
    return $normalized;
}

function wwa_get_allowed_origins(): array {
    $origins = array();
    $current_origin = wwa_get_current_site_origin();
    if($current_origin !== ''){
        $origins[$current_origin] = true;
    }

    foreach(wwa_get_ror_list() as $origin){
        $origins[$origin] = true;
    }

    $parsed = wp_parse_url(site_url());
    if(is_array($parsed) && !empty($parsed['host']) && wwa_is_loopback_host($parsed['host'])){
        $loopback = 'http://'.strtolower($parsed['host']);
        if(isset($parsed['port']) && intval($parsed['port']) > 0 && intval($parsed['port']) !== 80){
            $loopback .= ':'.intval($parsed['port']);
        }
        $origins[$loopback] = true;
    }

    return array_keys($origins);
}

function wwa_is_trusted_origin(string $origin): bool {
    $origin = wwa_normalize_origin($origin);
    return $origin !== '' && in_array($origin, wwa_get_allowed_origins(), true);
}

function wwa_assert_authentication_response_public_checks(PublicKeyCredential $publicKeyCredential, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions): void {
    if(!$publicKeyCredential->response instanceof AuthenticatorAssertionResponse){
        throw AuthenticatorResponseVerificationException::create('Invalid response type.');
    }

    if($publicKeyCredential->response->clientDataJSON->type !== 'webauthn.get'){
        throw AuthenticatorResponseVerificationException::create('Invalid client data type.');
    }

    if($publicKeyCredentialRequestOptions->challenge === '' || !hash_equals($publicKeyCredentialRequestOptions->challenge, $publicKeyCredential->response->clientDataJSON->challenge)){
        throw AuthenticatorResponseVerificationException::create('Invalid challenge.');
    }

    if(!wwa_is_trusted_origin($publicKeyCredential->response->clientDataJSON->origin)){
        throw AuthenticatorResponseVerificationException::create('Invalid origin.');
    }

    $top_origin = $publicKeyCredential->response->clientDataJSON->topOrigin;
    if($top_origin !== null){
        if($publicKeyCredential->response->clientDataJSON->crossOrigin !== true || !wwa_is_trusted_origin($top_origin)){
            throw AuthenticatorResponseVerificationException::create('Invalid top origin.');
        }
    }
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
        $blog_id = is_object($new_site) && isset($new_site->blog_id) ? intval($new_site->blog_id) : intval($new_site->id ?? 0);
        if($blog_id <= 0){
            return;
        }
        switch_to_blog($blog_id);
        wwa_init_data();
        wwa_apply_rewrite_rules();
        restore_current_blog();
    }
}
add_action('wp_initialize_site', 'wwa_new_site_init');

add_filter('query_vars', 'wwa_query_vars');
add_action('parse_request', 'wwa_handle_ror', 99);
add_action('init', 'wwa_add_rewrite_rules', 1);

// Normalize credential response JSON from standard base64 to base64url without padding
function wwa_normalize_credential_response(string $json_string): string {
    $data = json_decode($json_string, true);
    if(!is_array($data)){
        return $json_string;
    }

    $to_base64url = function($v){
        return is_string($v) ? rtrim(strtr($v, '+/', '-_'), '=') : $v;
    };

    if(isset($data['id']) && is_string($data['id'])){
        $data['id'] = $to_base64url($data['id']);
    }
    if(isset($data['rawId']) && is_string($data['rawId'])){
        $data['rawId'] = $to_base64url($data['rawId']);
    }

    if(isset($data['response']) && is_array($data['response'])){
        // Every binary field defined by the WebAuthn JSON spec
        foreach([
            'authenticatorData',
            'clientDataJSON',
            'attestationObject',
            'signature',
            'userHandle',
            'publicKey',
        ] as $field){
            if(isset($data['response'][$field]) && is_string($data['response'][$field])){
                $data['response'][$field] = $to_base64url($data['response'][$field]);
            }
        }
    }

    $encoded = wp_json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    return $encoded === false ? $json_string : $encoded;
}

// Build the COSE algorithm manager + attestation statement support manager
function wwa_get_webauthn_support_managers(){
    static $managers = null;
    if($managers !== null){
        return $managers;
    }

    $algorithmManager = CoseAlgorithmManager::create()
        ->add(Ed25519::create())   // -8
        ->add(ES256::create())     // -7
        ->add(ES384::create())     // -35
        ->add(ES512::create())     // -36
        ->add(PS256::create())     // -37
        ->add(PS384::create())     // -38
        ->add(PS512::create())     // -39
        ->add(RS256::create());    // -257

    $attestationStatementSupportManager = AttestationStatementSupportManager::create();
    $attestationStatementSupportManager->add(NoneAttestationStatementSupport::create());
    $attestationStatementSupportManager->add(FidoU2FAttestationStatementSupport::create());
    $attestationStatementSupportManager->add(AppleAttestationStatementSupport::create());
    $attestationStatementSupportManager->add(AndroidKeyAttestationStatementSupport::create());
    $attestationStatementSupportManager->add(TPMAttestationStatementSupport::create());
    $attestationStatementSupportManager->add(PackedAttestationStatementSupport::create($algorithmManager));
    $attestationStatementSupportManager->add(CompoundAttestationStatementSupport::create());

    $managers = [
        'algorithmManager' => $algorithmManager,
        'attestationStatementSupportManager' => $attestationStatementSupportManager,
    ];
    return $managers;
}

// Process-wide WebAuthn serializer
function wwa_get_webauthn_serializer(){
    static $serializer = null;
    if($serializer === null){
        $managers = wwa_get_webauthn_support_managers();
        $serializer = (new WebauthnSerializerFactory($managers['attestationStatementSupportManager']))->create();
    }
    return $serializer;
}

function wwa_get_server_components($current_domain = null){
    static $cache = [];
    $allowed_origins = wwa_get_allowed_origins();
    $key = md5(wp_json_encode($allowed_origins).'|'.wwa_get_current_site_host().'|'.(string) $current_domain);
    if(isset($cache[$key])){
        return $cache[$key];
    }

    $managers = wwa_get_webauthn_support_managers();
    $algorithmManager = $managers['algorithmManager'];
    $attestationStatementSupportManager = $managers['attestationStatementSupportManager'];

    $serializer = wwa_get_webauthn_serializer();

    $ceremonyStepManagerFactory = new CeremonyStepManagerFactory();
    $ceremonyStepManagerFactory->setAttestationStatementSupportManager($attestationStatementSupportManager);
    $ceremonyStepManagerFactory->setExtensionOutputCheckerHandler(ExtensionOutputCheckerHandler::create());
    $ceremonyStepManagerFactory->setAlgorithmManager($algorithmManager);
    $ceremonyStepManagerFactory->setAllowedOrigins($allowed_origins, false);

    $ceremonyStepManagerFactory->enableTopOriginValidator(new class($allowed_origins) implements TopOriginValidator {
        private array $allowedOrigins;

        public function __construct(array $allowedOrigins) {
            $this->allowedOrigins = $allowedOrigins;
        }

        public function validate(string $topOrigin): void {
            $topOrigin = wwa_normalize_origin($topOrigin);
            if($topOrigin === '' || !in_array($topOrigin, $this->allowedOrigins, true)){
                throw AuthenticatorResponseVerificationException::create('Invalid top origin.');
            }
        }
    });

    $attestationValidator = AuthenticatorAttestationResponseValidator::create(
        ceremonyStepManager: $ceremonyStepManagerFactory->creationCeremony()
    );

    $assertionValidator = AuthenticatorAssertionResponseValidator::create(
        ceremonyStepManager: $ceremonyStepManagerFactory->requestCeremony()
    );

    $conditionalAttestationValidator = AuthenticatorAttestationResponseValidator::create(
        ceremonyStepManager: $ceremonyStepManagerFactory->conditionalCreateCeremony()
    );

    $cache[$key] = [
        'serializer' => $serializer,
        'attestationValidator' => $attestationValidator,
        'conditionalAttestationValidator' => $conditionalAttestationValidator,
        'assertionValidator' => $assertionValidator,
    ];
    return $cache[$key];
}

function wwa_get_unknown_credential_signal_payload(string $credential_id): array {
    $signal = new UnknownCredential(
        wwa_get_rp_entity(),
        PublicKeyCredentialDescriptor::create(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $credential_id)
    );

    $json = wwa_get_webauthn_serializer()->serialize($signal, 'json', [
        AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        'json_encode_options' => JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
    ]);
    $payload = json_decode($json, true);
    return is_array($payload) ? $payload : array();
}

function wwa_get_unknown_credential_signal_response_data(string $credential_id): array {
    if(is_multisite()){
        return array();
    }

    return array(
        'signal' => array(
            'type' => 'unknownCredential',
            'payload' => wwa_get_unknown_credential_signal_payload($credential_id),
        ),
    );
}

function wwa_get_current_user_details_signal_payload($user_info = null): array {
    if($user_info === null){
        $user_info = wp_get_current_user();
    }
    if(!$user_info || empty($user_info->ID)){
        return array();
    }

    $signal = new CurrentUserDetails(
        wwa_get_rp_entity(),
        wwa_get_user_entity($user_info)
    );

    $json = wwa_get_webauthn_serializer()->serialize($signal, 'json', [
        AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        'json_encode_options' => JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
    ]);
    $payload = json_decode($json, true);
    return is_array($payload) ? $payload : array();
}
