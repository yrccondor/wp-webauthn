<?php
if (!defined('ABSPATH')) {
    exit;
}

require_once('wp-webauthn-vendor/autoload.php');
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

class PublicKeyCredentialSourceRepository {
    private $registration_context = null;

    // Fetch the WebAuthn serializer used to (de)serialize PublicKeyCredentialSource
    // to/from its JSON DB representation
    private function serializer() {
        return wwa_get_webauthn_serializer();
    }

    // Decode a credential_source JSON row into a PublicKeyCredentialSource
    private function deserializeSource($raw): ?PublicKeyCredentialSource {
        try {
            if(is_array($raw)){
                $raw = wp_json_encode($raw);
                if($raw === false){
                    return null;
                }
            }
            if(!is_string($raw) || $raw === ''){
                return null;
            }
            return $this->serializer()->deserialize($raw, PublicKeyCredentialSource::class, 'json');
        } catch(\Throwable $e) {
            wwa_add_log(wwa_generate_random_string(5), 'Warning: Failed to deserialize credential source: '.$e->getMessage(), true);
            return null;
        }
    }

    private function serializeSource(PublicKeyCredentialSource $source): string {
        return $this->serializer()->serialize($source, 'json', [
            'json_encode_options' => JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ]);
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource {
        global $wpdb;
        $key = base64_encode($publicKeyCredentialId);

        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT credential_source FROM {$wpdb->wwa_credentials} WHERE credential_id = %s",
            $key
        ));
        if($row !== null){
            return $this->deserializeSource($row->credential_source);
        }

        if(!get_option('wwa_credentials_migrated')){
            $old = get_option('wwa_options');
            if(isset($old['user_credentials'])){
                $data = json_decode($old['user_credentials'], true);
                if(is_array($data) && isset($data[$key]) && is_array($data[$key])){
                    return $this->deserializeSource($data[$key]);
                }
            }
        }

        return null;
    }

    public function findOneMetaByCredentialId(string $publicKeyCredentialId): ?array {
        global $wpdb;
        $key = base64_encode($publicKeyCredentialId);

        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT user_handle, human_name, authenticator_type, usernameless, added, last_used
             FROM {$wpdb->wwa_credentials} WHERE credential_id = %s",
            $key
        ));
        if($row !== null){
            return array(
                'human_name' => $row->human_name,
                'added' => $row->added,
                'authenticator_type' => $row->authenticator_type,
                'user' => $row->user_handle,
                'usernameless' => (bool) $row->usernameless,
                'last_used' => $row->last_used,
            );
        }

        if(!get_option('wwa_credentials_migrated')){
            $old = get_option('wwa_options');
            if(isset($old['user_credentials_meta'])){
                $meta = json_decode($old['user_credentials_meta'], true);
                if(is_array($meta) && isset($meta[$key])){
                    return $meta[$key];
                }
            }
        }

        return null;
    }

    public function findAllForUserEntityByUserId(int $wp_user_id): array {
        global $wpdb;
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT credential_source FROM {$wpdb->wwa_credentials} WHERE user_id = %d",
            $wp_user_id
        ));
        $sources = [];
        foreach($rows as $row){
            $source = $this->deserializeSource($row->credential_source);
            if($source !== null){
                $sources[] = $source;
            }
        }
        return $sources;
    }

    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array {
        global $wpdb;
        $handle = $publicKeyCredentialUserEntity->id;

        $wp_user_id = $wpdb->get_var($wpdb->prepare(
            "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = 'wwa_user_handle' AND meta_value = %s LIMIT 1",
            $handle
        ));
        if($wp_user_id !== null){
            return $this->findAllForUserEntityByUserId(intval($wp_user_id));
        }

        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT credential_source FROM {$wpdb->wwa_credentials} WHERE user_handle = %s",
            $handle
        ));
        $sources = [];
        foreach($rows as $row){
            $source = $this->deserializeSource($row->credential_source);
            if($source !== null){
                $sources[] = $source;
            }
        }
        return $sources;
    }

    public function findCredentialsForUserEntityByType(int $wp_user_id, string $credentialType): array {
        global $wpdb;
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT credential_source FROM {$wpdb->wwa_credentials}
             WHERE user_id = %d AND authenticator_type = %s",
            $wp_user_id, $credentialType
        ));
        $sources = [];
        foreach($rows as $row){
            $source = $this->deserializeSource($row->credential_source);
            if($source !== null){
                $sources[] = $source;
            }
        }
        return $sources;
    }

    public function setRegistrationContext(int $user_id, string $name, string $type, bool $usernameless = false): void {
        $this->registration_context = compact('user_id', 'name', 'type', 'usernameless');
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void {
        global $wpdb;
        $cred_id = base64_encode($publicKeyCredentialSource->publicKeyCredentialId);

        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->wwa_credentials} WHERE credential_id = %s",
            $cred_id
        ));

        $serialized = $this->serializeSource($publicKeyCredentialSource);

        if($exists > 0){
            $wpdb->update(
                $wpdb->wwa_credentials,
                array('credential_source' => $serialized),
                array('credential_id' => $cred_id)
            );
            return;
        }

        if($this->registration_context === null){
            return;
        }

        $ctx = $this->registration_context;
        $wpdb->insert($wpdb->wwa_credentials, array(
            'credential_id' => $cred_id,
            'user_id' => $ctx['user_id'],
            'registered_blog_id' => get_current_blog_id(),
            'credential_source' => $serialized,
            'user_handle' => $publicKeyCredentialSource->userHandle,
            'human_name' => base64_encode(sanitize_text_field($ctx['name'])),
            'authenticator_type' => sanitize_text_field($ctx['type']),
            'usernameless' => $ctx['usernameless'] ? 1 : 0,
            'added' => current_time('mysql'),
            'last_used' => '-',
        ));
        $this->registration_context = null;
    }

    public function updateCredentialLastUsed(string $publicKeyCredentialId): void {
        global $wpdb;
        $wpdb->update(
            $wpdb->wwa_credentials,
            array('last_used' => current_time('mysql')),
            array('credential_id' => base64_encode($publicKeyCredentialId))
        );
    }

    public function getShowListByUserId(int $wp_user_id): array {
        global $wpdb;
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT credential_id, human_name, authenticator_type, added, usernameless, last_used
             FROM {$wpdb->wwa_credentials}
             WHERE user_id = %d AND registered_blog_id = %d
             ORDER BY added ASC",
            $wp_user_id, get_current_blog_id()
        ));
        return array_map(function($row){
            return array(
                'key' => rtrim(strtr($row->credential_id, '+/', '-_'), '='),
                'name' => esc_html(base64_decode($row->human_name)),
                'type' => $row->authenticator_type,
                'added' => $row->added,
                'usernameless' => (bool) $row->usernameless,
                'last_used' => $row->last_used,
            );
        }, $rows);
    }

    public function renameCredential(string $credential_id_urlsafe, int $wp_user_id, string $new_name, string $res_id): bool {
        global $wpdb;
        $credential_id = base64_encode(base64_decode(strtr($credential_id_urlsafe, '-_', '+/')));
        wwa_add_log($res_id, "ajax_modify_authenticator: Rename credential");
        $affected = $wpdb->update(
            $wpdb->wwa_credentials,
            array('human_name' => base64_encode(sanitize_text_field($new_name))),
            array('credential_id' => $credential_id, 'user_id' => $wp_user_id, 'registered_blog_id' => get_current_blog_id())
        );
        return $affected !== false;
    }

    public function removeCredential(string $credential_id_urlsafe, int $wp_user_id, string $res_id): bool {
        global $wpdb;
        $credential_id = base64_encode(base64_decode(strtr($credential_id_urlsafe, '-_', '+/')));
        wwa_add_log($res_id, "ajax_modify_authenticator: Remove credential");
        $affected = $wpdb->delete(
            $wpdb->wwa_credentials,
            array('credential_id' => $credential_id, 'user_id' => $wp_user_id, 'registered_blog_id' => get_current_blog_id())
        );
        return $affected > 0;
    }
}
