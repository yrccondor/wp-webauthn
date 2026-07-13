<?php
if (!defined('ABSPATH')) {
    exit;
}

require_once('wp-webauthn-vendor/autoload.php');
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;

class CredentialRecordRepository {
    private $registration_context = null;

    private function serializer() {
        return wwa_get_webauthn_serializer();
    }

    private function normalizeRecord(CredentialRecord $record): CredentialRecord {
        if(get_class($record) === CredentialRecord::class){
            return $record;
        }

        return CredentialRecord::create(
            $record->publicKeyCredentialId,
            $record->type,
            $record->transports,
            $record->attestationType,
            $record->trustPath,
            $record->aaguid,
            $record->credentialPublicKey,
            $record->userHandle,
            $record->counter,
            $record->otherUI,
            $record->backupEligible,
            $record->backupStatus,
            $record->uvInitialized
        );
    }

    private function deserializeRecord($raw): ?CredentialRecord {
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
            return $this->normalizeRecord($this->serializer()->deserialize($raw, CredentialRecord::class, 'json'));
        } catch(\Throwable $primary) {
            try {
                $legacy_raw = $this->normalizeLegacyCredentialRecordJson($raw);
                if($legacy_raw === null){
                    throw $primary;
                }
                $legacy_record = $this->serializer()->deserialize($legacy_raw, CredentialRecord::class, 'json');
                return $this->normalizeRecord($legacy_record);
            } catch(\Throwable) {
                return null;
            }
        }
    }

    private function normalizeLegacyCredentialRecordJson(string $raw): ?string {
        $data = json_decode($raw, true);
        if(!is_array($data)){
            return null;
        }

        $changed = false;

        if(isset($data['aaguid']) && is_string($data['aaguid'])){
            try{
                Uuid::fromString($data['aaguid']);
            }catch(\Throwable){
                $aaguid = wwa_decode_base64_or_base64url($data['aaguid']);
                if(strlen($aaguid) === 16){
                    $data['aaguid'] = Uuid::fromBinary($aaguid)->toRfc4122();
                    $changed = true;
                }
            }
        }

        if(isset($data['trustPath']) && is_array($data['trustPath']) && isset($data['trustPath']['type']) && $data['trustPath']['type'] === 'empty'){
            $data['trustPath'] = array();
            $changed = true;
        }

        if(!$changed){
            return null;
        }

        $normalized = wp_json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return is_string($normalized) ? $normalized : null;
    }

    private function serializeRecord(CredentialRecord $record): string {
        return $this->serializer()->serialize($this->normalizeRecord($record), 'json', [
            'json_encode_options' => JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ]);
    }

    private function throwDatabaseWriteError(string $operation): void {
        global $wpdb;
        $message = $wpdb->last_error ? ': '.$wpdb->last_error : '';
        throw new \RuntimeException('Failed to '.$operation.' credential record'.$message);
    }

    private function descriptorFromStoredRow($row): ?PublicKeyCredentialDescriptor {
        $credential_id = wwa_decode_base64_or_base64url($row->credential_id);
        if($credential_id === ''){
            return null;
        }

        $type = PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY;
        $transports = array();
        $source = isset($row->credential_source) ? json_decode($row->credential_source, true) : null;

        if(is_array($source)){
            if(isset($source['type']) && $source['type'] === PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY){
                $type = $source['type'];
            }
            if(isset($source['transports']) && is_array($source['transports'])){
                $transports = array_values(array_filter($source['transports'], function($transport){
                    return is_string($transport) && in_array($transport, PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORTS, true);
                }));
            }
        }elseif(isset($row->credential_source)){
            $record = $this->deserializeRecord($row->credential_source);
            return $record === null ? null : $record->getPublicKeyCredentialDescriptor();
        }

        return PublicKeyCredentialDescriptor::create($type, $credential_id, $transports);
    }

    private function normalizeBlogIds(?array $blog_ids): ?array {
        if($blog_ids === null){
            return null;
        }
        return wwa_normalize_blog_id_list($blog_ids);
    }

    private function buildBlogScopeClause(?array $blog_ids, array &$params): ?string {
        $blog_ids = $this->normalizeBlogIds($blog_ids);
        if($blog_ids === null){
            return '';
        }
        if(count($blog_ids) === 0){
            return null;
        }

        $params = array_merge($params, $blog_ids);
        return ' AND registered_blog_id IN ('.implode(', ', array_fill(0, count($blog_ids), '%d')).')';
    }

    private function blogScopeAllowsCurrentSite(?array $blog_ids): bool {
        if($blog_ids === null){
            return true;
        }
        return in_array(get_current_blog_id(), $this->normalizeBlogIds($blog_ids), true);
    }

    private function legacyCredentialMetaMatchesUser($meta, ?int $wp_user_id): bool {
        if($wp_user_id === null || $wp_user_id <= 0){
            return true;
        }
        if(!is_array($meta) || !isset($meta['user']) || !is_string($meta['user'])){
            return false;
        }

        $legacy_handle = $meta['user'];
        $stored_handle = get_user_meta($wp_user_id, 'wwa_user_handle', true);
        if(is_string($stored_handle) && $stored_handle !== '' && hash_equals($stored_handle, $legacy_handle)){
            return true;
        }

        $wp_user = get_user_by('id', $wp_user_id);
        $user_id_map = wwa_get_option('user_id');
        return $wp_user !== false
            && is_array($user_id_map)
            && isset($user_id_map[$wp_user->user_login])
            && is_string($user_id_map[$wp_user->user_login])
            && hash_equals($user_id_map[$wp_user->user_login], $legacy_handle);
    }

    public function findOneByCredentialId(string $publicKeyCredentialId, ?array $blog_ids = null, ?int $wp_user_id = null): ?CredentialRecord {
        global $wpdb;
        $key = wwa_credential_storage_id($publicKeyCredentialId);
        $hash = wwa_credential_hash($publicKeyCredentialId);
        $params = array($hash);
        $user_sql = '';
        if($wp_user_id !== null && $wp_user_id > 0){
            $user_sql = ' AND user_id = %d';
            $params[] = $wp_user_id;
        }
        $blog_sql = $this->buildBlogScopeClause($blog_ids, $params);
        if($blog_sql === null){
            return null;
        }

        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT credential_source FROM {$wpdb->wwa_credentials} WHERE credential_hash = %s{$user_sql}{$blog_sql} ORDER BY id ASC LIMIT 1",
            $params
        ));
        if($row !== null){
            return $this->deserializeRecord($row->credential_source);
        }

        if(!is_multisite() && !get_option('wwa_credentials_migrated') && $this->blogScopeAllowsCurrentSite($blog_ids)){
            if($wp_user_id !== null && $wp_user_id > 0 && $this->findOneMetaByCredentialId($publicKeyCredentialId, $blog_ids, $wp_user_id) === null){
                return null;
            }
            $old = get_option('wwa_options');
            if(isset($old['user_credentials'])){
                $data = json_decode($old['user_credentials'], true);
                if(is_array($data) && isset($data[$key]) && is_array($data[$key])){
                    return $this->deserializeRecord($data[$key]);
                }
            }
        }

        return null;
    }

    public function findOneMetaByCredentialId(string $publicKeyCredentialId, ?array $blog_ids = null, ?int $wp_user_id = null): ?array {
        global $wpdb;
        $key = wwa_credential_storage_id($publicKeyCredentialId);
        $hash = wwa_credential_hash($publicKeyCredentialId);
        $params = array($hash);
        $user_sql = '';
        if($wp_user_id !== null && $wp_user_id > 0){
            $user_sql = ' AND user_id = %d';
            $params[] = $wp_user_id;
        }
        $blog_sql = $this->buildBlogScopeClause($blog_ids, $params);
        if($blog_sql === null){
            return null;
        }

        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT id, user_id, registered_blog_id, user_handle, human_name, authenticator_type, usernameless, added, last_used
             FROM {$wpdb->wwa_credentials} WHERE credential_hash = %s{$user_sql}{$blog_sql} ORDER BY id ASC LIMIT 1",
            $params
        ));
        if($row !== null){
            return array(
                'id' => intval($row->id),
                'user_id' => intval($row->user_id),
                'registered_blog_id' => intval($row->registered_blog_id),
                'human_name' => $row->human_name,
                'added' => $row->added,
                'authenticator_type' => $row->authenticator_type,
                'user' => $row->user_handle,
                'user_handle' => $row->user_handle,
                'usernameless' => (bool) $row->usernameless,
                'last_used' => $row->last_used,
            );
        }

        if(!is_multisite() && !get_option('wwa_credentials_migrated') && $this->blogScopeAllowsCurrentSite($blog_ids)){
            $old = get_option('wwa_options');
            if(isset($old['user_credentials_meta'])){
                $meta = json_decode($old['user_credentials_meta'], true);
                if(is_array($meta) && isset($meta[$key])){
                    if(!$this->legacyCredentialMetaMatchesUser($meta[$key], $wp_user_id)){
                        return null;
                    }
                    return $meta[$key];
                }
            }
        }

        return null;
    }

    public function findCredentialDescriptorsForUserId(int $wp_user_id, ?string $credentialType = null, ?array $blog_ids = null): array {
        global $wpdb;
        $params = array($wp_user_id);
        $type_sql = '';
        if($credentialType !== null && $credentialType !== 'none'){
            $type_sql = ' AND authenticator_type = %s';
            $params[] = $credentialType;
        }
        $blog_sql = $this->buildBlogScopeClause($blog_ids, $params);
        if($blog_sql === null){
            return array();
        }

        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT credential_id, credential_source FROM {$wpdb->wwa_credentials}
             WHERE user_id = %d{$type_sql}{$blog_sql}",
            $params
        ));

        $descriptors = array();
        foreach($rows as $row){
            $descriptor = $this->descriptorFromStoredRow($row);
            if($descriptor !== null){
                $descriptors[] = $descriptor;
            }
        }
        return $descriptors;
    }

    public function userHasCredentials(int $wp_user_id, ?array $blog_ids = null): bool {
        global $wpdb;
        $params = array($wp_user_id);
        $blog_sql = $this->buildBlogScopeClause($blog_ids, $params);
        if($blog_sql === null){
            return false;
        }
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT 1 FROM {$wpdb->wwa_credentials} WHERE user_id = %d{$blog_sql} LIMIT 1",
            $params
        ));
        return $exists !== null;
    }

    public function setRegistrationContext(int $user_id, string $name, string $type, bool $usernameless = false): void {
        $this->registration_context = compact('user_id', 'name', 'type', 'usernameless');
    }

    public function saveCredentialRecord(CredentialRecord $credentialRecord): void {
        global $wpdb;
        $credentialRecord = $this->normalizeRecord($credentialRecord);
        $cred_id = wwa_credential_storage_id($credentialRecord->publicKeyCredentialId);
        $credential_hash = wwa_credential_hash($credentialRecord->publicKeyCredentialId);

        $existing_id = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM {$wpdb->wwa_credentials} WHERE credential_hash = %s ORDER BY id ASC LIMIT 1",
            $credential_hash
        ));

        $serialized = $this->serializeRecord($credentialRecord);

        if($existing_id !== null){
            if($this->registration_context !== null){
                $this->registration_context = null;
                throw new \RuntimeException('Credential ID already registered');
            }
            $updated = $wpdb->update(
                $wpdb->wwa_credentials,
                array('credential_source' => $serialized),
                array('id' => intval($existing_id))
            );
            if($updated === false){
                $this->throwDatabaseWriteError('update');
            }
            $this->registration_context = null;
            return;
        }

        if($this->registration_context === null){
            return;
        }

        $ctx = $this->registration_context;
        $inserted = $wpdb->insert($wpdb->wwa_credentials, array(
            'credential_hash' => $credential_hash,
            'credential_id' => $cred_id,
            'user_id' => $ctx['user_id'],
            'registered_blog_id' => get_current_blog_id(),
            'credential_source' => $serialized,
            'user_handle' => $credentialRecord->userHandle,
            'human_name' => base64_encode(sanitize_text_field($ctx['name'])),
            'authenticator_type' => sanitize_text_field($ctx['type']),
            'usernameless' => $ctx['usernameless'] ? 1 : 0,
            'added' => current_time('mysql'),
            'last_used' => '-',
        ));
        if($inserted === false){
            $this->throwDatabaseWriteError('insert');
        }
        $this->registration_context = null;
    }

    public function updateCredentialLastUsed(string $publicKeyCredentialId, ?array $blog_ids = null, ?int $wp_user_id = null): void {
        global $wpdb;
        $params = array(current_time('mysql'), wwa_credential_hash($publicKeyCredentialId));
        $user_sql = '';
        if($wp_user_id !== null && $wp_user_id > 0){
            $user_sql = ' AND user_id = %d';
            $params[] = $wp_user_id;
        }
        $blog_sql = $this->buildBlogScopeClause($blog_ids, $params);
        if($blog_sql === null){
            return;
        }
        $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->wwa_credentials}
             SET last_used = %s
             WHERE credential_hash = %s{$user_sql}{$blog_sql}
             ORDER BY id ASC LIMIT 1",
            $params
        ));
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
            $key = wwa_credential_storage_id_to_urlsafe($row->credential_id);
            return array(
                'key' => $key,
                'name' => sanitize_text_field(base64_decode($row->human_name)),
                'type' => $row->authenticator_type,
                'added' => $row->added,
                'usernameless' => (bool) $row->usernameless,
                'last_used' => $row->last_used,
            );
        }, $rows);
    }

    public function renameCredential(string $credential_id_urlsafe, int $wp_user_id, string $new_name, string $res_id): bool {
        global $wpdb;
        $credential_hash = wwa_credential_hash_from_encoded_id($credential_id_urlsafe);
        $new_name = sanitize_text_field($new_name);
        if($credential_hash === '' || $new_name === ''){
            return false;
        }
        wwa_add_log($res_id, "ajax_modify_authenticator: Rename credential");
        $where = array(
            'credential_hash' => $credential_hash,
            'user_id' => $wp_user_id,
            'registered_blog_id' => get_current_blog_id(),
        );
        $affected = $wpdb->update(
            $wpdb->wwa_credentials,
            array('human_name' => base64_encode($new_name)),
            $where
        );
        if($affected === false){
            return false;
        }
        if($affected > 0){
            return true;
        }

        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT 1 FROM {$wpdb->wwa_credentials}
             WHERE credential_hash = %s AND user_id = %d AND registered_blog_id = %d
             LIMIT 1",
            $credential_hash,
            $wp_user_id,
            get_current_blog_id()
        ));
        return $exists !== null;
    }

    public function removeCredential(string $credential_id_urlsafe, int $wp_user_id, string $res_id): bool {
        global $wpdb;
        $credential_hash = wwa_credential_hash_from_encoded_id($credential_id_urlsafe);
        if($credential_hash === ''){
            return false;
        }
        wwa_add_log($res_id, "ajax_modify_authenticator: Remove credential");
        $affected = $wpdb->delete(
            $wpdb->wwa_credentials,
            array('credential_hash' => $credential_hash, 'user_id' => $wp_user_id, 'registered_blog_id' => get_current_blog_id())
        );
        return $affected > 0;
    }
}
