<?php
if (!defined('ABSPATH')) {
    exit;
}

require_once('wp-webauthn-vendor/autoload.php');
use Webauthn\Server;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialDescriptor;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;

class PublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepositoryInterface {
    private $registration_context = null;

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource {
        global $wpdb;
        $key = base64_encode($publicKeyCredentialId);

        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT credential_source FROM {$wpdb->wwa_credentials} WHERE credential_id = %s",
            $key
        ));
        if($row !== null){
            $decoded = json_decode($row->credential_source, true);
            if(is_array($decoded)){
                try {
                    return PublicKeyCredentialSource::createFromArray($decoded);
                } catch(\Throwable $e) {
                    return null;
                }
            }
            return null;
        }

        if(!get_option('wwa_credentials_migrated')){
            $old = get_option('wwa_options');
            if(isset($old['user_credentials'])){
                $data = json_decode($old['user_credentials'], true);
                if(is_array($data) && isset($data[$key]) && is_array($data[$key])){
                    try {
                        return PublicKeyCredentialSource::createFromArray($data[$key]);
                    } catch(\Throwable $e) {
                        return null;
                    }
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
            $decoded = json_decode($row->credential_source, true);
            if(!is_array($decoded)){
                continue;
            }
            try {
                $sources[] = PublicKeyCredentialSource::createFromArray($decoded);
            } catch(\Throwable $e) {
                continue;
            }
        }
        return $sources;
    }

    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array {
        global $wpdb;
        $handle = $publicKeyCredentialUserEntity->getId();

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
            $decoded = json_decode($row->credential_source, true);
            if(!is_array($decoded)){
                continue;
            }
            try {
                $sources[] = PublicKeyCredentialSource::createFromArray($decoded);
            } catch(\Throwable $e) {
                continue;
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
            $decoded = json_decode($row->credential_source, true);
            if(!is_array($decoded)){
                continue;
            }
            try {
                $sources[] = PublicKeyCredentialSource::createFromArray($decoded);
            } catch(\Throwable $e) {
                continue;
            }
        }
        return $sources;
    }

    public function setRegistrationContext(int $user_id, string $name, string $type, bool $usernameless = false): void {
        $this->registration_context = compact('user_id', 'name', 'type', 'usernameless');
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void {
        global $wpdb;
        $cred_id = base64_encode($publicKeyCredentialSource->getPublicKeyCredentialId());

        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->wwa_credentials} WHERE credential_id = %s",
            $cred_id
        ));

        if($exists > 0){
            $wpdb->update(
                $wpdb->wwa_credentials,
                array('credential_source' => wp_json_encode($publicKeyCredentialSource)),
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
            'credential_source' => wp_json_encode($publicKeyCredentialSource),
            'user_handle' => $publicKeyCredentialSource->getUserHandle(),
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
             WHERE user_id = %d AND registered_blog_id = %d",
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

// Bind an authenticator
function wwa_ajax_create(){
    check_ajax_referer('wwa_ajax');
    $client_id = false;
    try{
        $res_id = wwa_generate_random_string(5);
        $client_id = strval(time()).wwa_generate_random_string(24);

        wwa_init_new_options();

        wwa_add_log($res_id, "ajax_create: Start");

        if(!current_user_can("read")){
            wwa_add_log($res_id, "ajax_create: (ERROR)Permission denied, exit");
            wwa_wp_die("Something went wrong.", $client_id);
        }

        if(wwa_get_option("website_name") === "" || wwa_get_option('website_domain') ===""){
            wwa_add_log($res_id, "ajax_create: (ERROR)Plugin not configured, exit");
            wwa_wp_die("Not configured.", $client_id);
        }

        // Check queries
        if(!isset($_GET["name"]) || !isset($_GET["type"]) || !isset($_GET["usernameless"])){
            wwa_add_log($res_id, "ajax_create: (ERROR)Missing parameters, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }else{
            // Sanitize the input
            $wwa_get = array();
            $wwa_get["name"] = sanitize_text_field(wp_unslash($_GET["name"]));
            $wwa_get["type"] = sanitize_text_field(wp_unslash($_GET["type"]));
            $wwa_get["usernameless"] = sanitize_text_field(wp_unslash($_GET["usernameless"]));
            wwa_add_log($res_id, "ajax_create: name => \"".$wwa_get["name"]."\", type => \"".$wwa_get["type"]."\", usernameless => \"".$wwa_get["usernameless"]."\"");
        }

        $user_info = wp_get_current_user();

        if(isset($_GET["user_id"])){
            $user_id = intval(sanitize_text_field(wp_unslash($_GET["user_id"])));
            if($user_id <= 0){
                wwa_add_log($res_id, "ajax_create: (ERROR)Wrong parameters, exit");
                wwa_wp_die("Bad Request.");
            }

            if($user_info->ID !== $user_id){
                if(!current_user_can("edit_user", $user_id)){
                    wwa_add_log($res_id, "ajax_create: (ERROR)No permission, exit");
                    wwa_wp_die("Something went wrong.");
                }
                $user_info = get_user_by('id', $user_id);

                if($user_info === false){
                    wwa_add_log($res_id, "ajax_create: (ERROR)Wrong user ID, exit");
                    wwa_wp_die("Something went wrong.");
                }
            }
        }

        // Empty authenticator name
        if($wwa_get["name"] === ""){
            wwa_add_log($res_id, "ajax_create: (ERROR)Empty name, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }

        // Usernameless authentication not allowed
        if($wwa_get["usernameless"] === "true" && wwa_get_option("usernameless_login") !== "true"){
            wwa_add_log($res_id, "ajax_create: (ERROR)Usernameless authentication not allowed, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }

        // Check authenticator type
        $allow_authenticator_type = wwa_get_option("allow_authenticator_type");
        if($allow_authenticator_type !== false && $allow_authenticator_type !== "none"){
            if($allow_authenticator_type != $wwa_get["type"]){
                wwa_add_log($res_id, "ajax_create: (ERROR)Credential type error, type => \"".$wwa_get["type"]."\", allow_authenticator_type => \"".$allow_authenticator_type."\", exit");
                wwa_wp_die("Bad Request.", $client_id);
            }
        }

        $rpEntity = new PublicKeyCredentialRpEntity(
            wwa_get_option("website_name"),
            wwa_get_option("website_domain")
        );
        $publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();

        $server = new Server(
            $rpEntity,
            $publicKeyCredentialSourceRepository,
            null
        );

        wwa_add_log($res_id, "ajax_create: user => \"".$user_info->user_login."\"");

        // Get user ID or create one
        $user_key = get_user_meta($user_info->ID, 'wwa_user_handle', true);
        if(!$user_key){
            $user_id_map = wwa_get_option("user_id");
            if(is_array($user_id_map) && isset($user_id_map[$user_info->user_login])){
                $user_key = $user_id_map[$user_info->user_login];
                update_user_meta($user_info->ID, 'wwa_user_handle', $user_key);
            }else{
                wwa_add_log($res_id, "ajax_create: User not initialized, initialize");
                $user_key = hash("sha256", $user_info->user_login."-".$user_info->display_name."-".wwa_generate_random_string(10));
                update_user_meta($user_info->ID, 'wwa_user_handle', $user_key);
            }
        }

        $user = array(
            "login" => $user_info->user_login,
            "id" => $user_key,
            "display" => $user_info->display_name,
            "icon" => get_avatar_url($user_info->user_email, array("scheme" => "https"))
        );

        $userEntity = new PublicKeyCredentialUserEntity(
            $user["login"],
            $user["id"],
            $user["display"],
            $user["icon"]
        );

        $credentialSourceRepository = new PublicKeyCredentialSourceRepository();

        $credentialSources = $credentialSourceRepository->findAllForUserEntityByUserId($user_info->ID);

        // Convert the Credential Sources into Public Key Credential Descriptors for excluding
        $excludeCredentials = array_map(function (PublicKeyCredentialSource $credential) {
            return $credential->getPublicKeyCredentialDescriptor();
        }, $credentialSources);

        wwa_add_log($res_id, "ajax_create: excludeCredentials => ".wp_json_encode($excludeCredentials));

        // Set authenticator type
        if($wwa_get["type"] === "platform"){
            $authenticator_type = AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM;
        }elseif($wwa_get["type"] === "cross-platform"){
            $authenticator_type = AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        }else{
            $authenticator_type = AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE;
        }

        // Set user verification
        if(wwa_get_option("user_verification") === "true"){
            wwa_add_log($res_id, "ajax_create: user_verification => \"true\"");
            $user_verification = AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED;
        }else{
            wwa_add_log($res_id, "ajax_create: user_verification => \"false\"");
            $user_verification = AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
        }

        $resident_key = false;
        // Set usernameless authentication
        if($wwa_get["usernameless"] === "true"){
            wwa_add_log($res_id, "ajax_create: Usernameless set, user_verification => \"true\"");
            $user_verification = AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED;
            $resident_key = true;
        }

        // Create authenticator selection
        $authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria(
            $authenticator_type,
            $resident_key,
            $user_verification
        );

        // Create a creation challenge
        $publicKeyCredentialCreationOptions = $server->generatePublicKeyCredentialCreationOptions(
            $userEntity,
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $excludeCredentials,
            $authenticatorSelectionCriteria
        );

        // Save for future use
        wwa_set_temp_val("pkcco", base64_encode(serialize($publicKeyCredentialCreationOptions)), $client_id);
        wwa_set_temp_val("bind_config", array("name" => $wwa_get["name"], "type" => $wwa_get["type"], "usernameless" => $resident_key), $client_id);

        header("Content-Type: application/json");
        $publicKeyCredentialCreationOptions = json_decode(wp_json_encode($publicKeyCredentialCreationOptions), true);
        $publicKeyCredentialCreationOptions["clientID"] = $client_id;
        echo wp_json_encode($publicKeyCredentialCreationOptions);
        wwa_add_log($res_id, "ajax_create: Challenge sent");
        exit;
    }catch(\Exception $exception){
        wwa_add_log($res_id, "ajax_create: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($exception));
        wwa_add_log($res_id, "ajax_create: (ERROR)Unknown error, exit");
        wwa_wp_die("Something went wrong.", $client_id);
    }catch(\Error $error){
        wwa_add_log($res_id, "ajax_create: (ERROR)".$error->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($error));
        wwa_add_log($res_id, "ajax_create: (ERROR)Unknown error, exit");
        wwa_wp_die("Something went wrong.", $client_id);
    }
}
add_action("wp_ajax_wwa_create" , "wwa_ajax_create");

// Verify the attestation
function wwa_ajax_create_response(){
    check_ajax_referer('wwa_ajax');
    $client_id = false;
    try{
        $res_id = wwa_generate_random_string(5);

        wwa_init_new_options();

        wwa_add_log($res_id, "ajax_create_response: Client response received");

        if(!isset($_POST["clientid"])){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Missing parameters, exit");
            wp_die("Bad Request.");
        }else{
            // Sanitize the input
            $post_client_id = sanitize_text_field(wp_unslash($_POST["clientid"]));
            if(strlen($post_client_id) < 34 || strlen($post_client_id) > 35){
                wwa_add_log($res_id, "ajax_create_response: (ERROR)Wrong client ID, exit");
                wwa_wp_die("Bad Request.", $client_id);
            }
            $client_id = $post_client_id;
        }

        if(!current_user_can("read")){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Permission denied, exit");
            wwa_wp_die("Something went wrong.", $client_id);
        }

        // Check POST
        if(!isset($_POST["data"]) || !isset($_POST["name"]) || !isset($_POST["type"]) || !isset($_POST["usernameless"])){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Missing parameters, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }else{
            // Sanitize the input
            $wwa_post = array();
            $wwa_post["name"] = sanitize_text_field(wp_unslash($_POST["name"]));
            $wwa_post["type"] = sanitize_text_field(wp_unslash($_POST["type"]));
            $wwa_post["usernameless"] = sanitize_text_field(wp_unslash($_POST["usernameless"]));
            wwa_add_log($res_id, "ajax_create_response: name => \"".$wwa_post["name"]."\", type => \"".$wwa_post["type"]."\", usernameless => \"".$wwa_post["usernameless"]."\"");
            wwa_add_log($res_id, "ajax_create_response: data => ".sanitize_text_field(base64_decode(sanitize_text_field(wp_unslash($_POST["data"])))));
        }

        if(isset($_POST["user_id"])){
            $user_id = intval(sanitize_text_field(wp_unslash($_POST["user_id"])));
            if($user_id <= 0){
                wwa_add_log($res_id, "ajax_create_response: (ERROR)Wrong parameters, exit");
                wwa_wp_die("Bad Request.");
            }

            if(wp_get_current_user()->ID !== $user_id){
                if(!current_user_can("edit_user", $user_id)){
                    wwa_add_log($res_id, "ajax_create_response: (ERROR)No permission, exit");
                    wwa_wp_die("Something went wrong.");
                }
            }
        }

        $temp_val = array(
            "pkcco" => wwa_get_temp_val("pkcco", $client_id),
            "bind_config" => wwa_get_temp_val("bind_config", $client_id)
        );

        // May not get the challenge yet
        if($temp_val["pkcco"] === false || $temp_val["bind_config"] === false){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Challenge not found in transient, exit");
            wwa_wp_die("Bad request.", $client_id);
        }

        // Check parameters
        if($temp_val["bind_config"]["type"] !== "platform" && $temp_val["bind_config"]["type"] !== "cross-platform" && $temp_val["bind_config"]["type"] !== "none"){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Wrong type, exit");
            wwa_wp_die("Bad request.", $client_id);
        }

        if($temp_val["bind_config"]["type"] !== $wwa_post["type"] || $temp_val["bind_config"]["name"] !== $wwa_post["name"]){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Wrong parameters, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }

        if(!isset($_POST["data"]) || $_POST["data"] === ""){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Empty data, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }

        // Check global unique credential ID
        $credential_id = base64_decode(json_decode(base64_decode(sanitize_text_field(wp_unslash($_POST["data"]))), true)["rawId"]);
        $publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();
        if($publicKeyCredentialSourceRepository->findOneMetaByCredentialId($credential_id) !== null){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Credential ID not unique, ID => \"".base64_encode($credential_id)."\" , exit");
            wwa_wp_die("Something went wrong.", $client_id);
        }else{
            wwa_add_log($res_id, "ajax_create_response: Credential ID unique check passed");
        }

        $psr17Factory = new Psr17Factory();
        $creator = new ServerRequestCreator(
            $psr17Factory,
            $psr17Factory,
            $psr17Factory,
            $psr17Factory
        );

        $serverRequest = $creator->fromGlobals();

        $rpEntity = new PublicKeyCredentialRpEntity(
            wwa_get_option("website_name"),
            wwa_get_option("website_domain")
        );

        $server = new Server(
            $rpEntity,
            $publicKeyCredentialSourceRepository,
            null
        );

        // Allow to bypass scheme verification when under localhost
        $current_domain = wwa_get_option('website_domain');
        if($current_domain === "localhost" || $current_domain === "127.0.0.1"){
            $server->setSecuredRelyingPartyId([$current_domain]);
            wwa_add_log($res_id, "ajax_create_response: Localhost, bypass HTTPS check");
        }

        // Verify
        try {
            $publicKeyCredentialSource = $server->loadAndCheckAttestationResponse(
                base64_decode(sanitize_text_field(wp_unslash($_POST["data"]))),
                unserialize(base64_decode($temp_val["pkcco"]), ['allowed_classes' => [
                    Webauthn\PublicKeyCredentialCreationOptions::class,
                    Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs::class,
                    Webauthn\PublicKeyCredentialRpEntity::class,
                    Webauthn\PublicKeyCredentialUserEntity::class,
                    Webauthn\AuthenticatorSelectionCriteria::class,
                ]]),
                $serverRequest
            );

            wwa_add_log($res_id, "ajax_create_response: Challenge verified");

            $user_info = isset($_POST["user_id"]) ? get_user_by('id', intval(sanitize_text_field(wp_unslash($_POST["user_id"])))) : wp_get_current_user();
            $publicKeyCredentialSourceRepository->setRegistrationContext(
                $user_info->ID,
                $wwa_post["name"],
                $wwa_post["type"],
                $temp_val["bind_config"]["usernameless"]
            );
            $publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);

            if($temp_val["bind_config"]["usernameless"]){
                wwa_add_log($res_id, "ajax_create_response: Authenticator added with usernameless authentication feature");
            }else{
                wwa_add_log($res_id, "ajax_create_response: Authenticator added");
            }

            // Success
            echo "true";
        }catch(\Throwable $exception){
            // Failed to verify
            wwa_add_log($res_id, "ajax_create_response: (ERROR)".$exception->getMessage());
            wwa_add_log($res_id, wwa_generate_call_trace($exception));
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Challenge not verified, exit");
            wwa_wp_die("Something went wrong.", $client_id);
        }

        // Destroy transients
        wwa_destroy_temp_val($client_id);
        exit;
    }catch(\Exception $exception){
        wwa_add_log($res_id, "ajax_create_response: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($exception));
        wwa_add_log($res_id, "ajax_create_response: (ERROR)Unknown error, exit");
        wwa_wp_die("Something went wrong.", $client_id);
    }catch(\Error $error){
        wwa_add_log($res_id, "ajax_create_response: (ERROR)".$error->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($error));
        wwa_add_log($res_id, "ajax_create_response: (ERROR)Unknown error, exit");
        wwa_wp_die("Something went wrong.", $client_id);
    }
}
add_action("wp_ajax_wwa_create_response" , "wwa_ajax_create_response");

// Auth challenge
function wwa_ajax_auth_start(){
    $client_id = false;
    try{
        $res_id = wwa_generate_random_string(5);
        $client_id = strval(time()).wwa_generate_random_string(24);

        wwa_init_new_options();

        $is_conditional = isset($_GET['conditional']) && $_GET['conditional'] === 'true';
        wwa_add_log($res_id, "ajax_auth: Start" . ($is_conditional ? " (conditional)" : ""));

        // Check queries
        if(!isset($_GET["type"])){
            wwa_add_log($res_id, "ajax_auth: (ERROR)Missing parameters, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }else{
            // Sanitize the input
            $wwa_get = array();
            $wwa_get["type"] = sanitize_text_field(wp_unslash($_GET["type"]));
            if(isset($_GET["user"])){
                $wwa_get["user"] = sanitize_text_field(wp_unslash($_GET["user"]));
            }
            if(isset($_GET["usernameless"])){
                $wwa_get["usernameless"] = sanitize_text_field(wp_unslash($_GET["usernameless"]));
                // Usernameless authentication not allowed
                if($wwa_get["usernameless"] === "true" && wwa_get_option("usernameless_login") !== "true"){
                    wwa_add_log($res_id, "ajax_auth: (ERROR)Usernameless authentication not allowed, exit");
                    wwa_wp_die("Bad Request.", $client_id);
                }
            }
        }

        if($wwa_get["type"] === "test" && !current_user_can('read')){
            // Test but not logged in
            wwa_add_log($res_id, "ajax_auth: (ERROR)Permission denied, exit");
            wwa_wp_die("Bad request.", $client_id);
        }

        $user_key = "";
        $usernameless_flag = false;
        $user_icon = null;
        $user_exist = true;
        if($wwa_get["type"] === "test"){
            if(isset($wwa_get["usernameless"])){
                if($wwa_get["usernameless"] !== "true"){
                    // Logged in and testing, if the user haven't bound any authenticator yet, exit
                    $user_info = wp_get_current_user();

                    if(isset($_GET["user_id"])){
                        $user_id = intval(sanitize_text_field(wp_unslash($_GET["user_id"])));
                        if($user_id <= 0){
                            wwa_add_log($res_id, "ajax_auth: (ERROR)Wrong parameters, exit");
                            wwa_wp_die("Bad Request.");
                        }

                        if($user_info->ID !== $user_id){
                            if(!current_user_can("edit_user", $user_id)){
                                wwa_add_log($res_id, "ajax_auth: (ERROR)No permission, exit");
                                wwa_wp_die("Something went wrong.");
                            }
                            $user_info = get_user_by('id', $user_id);

                            if($user_info === false){
                                wwa_add_log($res_id, "ajax_auth: (ERROR)Wrong user ID, exit");
                                wwa_wp_die("Something went wrong.");
                            }
                        }
                    }

                    wwa_add_log($res_id, "ajax_auth: type => \"test\", user => \"".$user_info->user_login."\", usernameless => \"false\"");

                    $user_key = get_user_meta($user_info->ID, 'wwa_user_handle', true);
                    if(!$user_key){
                        $user_id_map = wwa_get_option("user_id");
                        if(is_array($user_id_map) && isset($user_id_map[$user_info->user_login])){
                            $user_key = $user_id_map[$user_info->user_login];
                        }else{
                            wwa_add_log($res_id, "ajax_auth: (ERROR)User not initialized, exit");
                            wwa_wp_die("User not inited.", $client_id);
                        }
                    }
                    $user_icon = get_avatar_url($user_info->user_email, array("scheme" => "https"));
                }else{
                    if(wwa_get_option("usernameless_login") === "true"){
                        wwa_add_log($res_id, "ajax_auth: type => \"test\", usernameless => \"true\"");
                        $usernameless_flag = true;
                    }else{
                        wwa_add_log($res_id, "ajax_auth: (ERROR)Wrong parameters, exit");
                        wwa_wp_die("Bad Request.", $client_id);
                    }
                }
            }else{
                wwa_add_log($res_id, "ajax_auth: (ERROR)Missing parameters, exit");
                wwa_wp_die("Bad Request.", $client_id);
            }
        }else{
            // Not testing, create a fake user ID if the user does not exist or haven't bound any authenticator yet
            if(isset($wwa_get["user"]) && $wwa_get["user"] !== ""){
                $wp_user = wwa_get_user($wwa_get["user"]);
                if(wwa_get_option("email_login") === "true" && is_email($wwa_get["user"])){
                    wwa_add_log($res_id, "ajax_auth: email_login => \"true\", trying to find user by email address \"".$wwa_get["user"]."\"");
                }
                if($wp_user !== false){
                    $user_info = $wp_user;
                    $user_icon = get_avatar_url($user_info->user_email, array("scheme" => "https"));
                    wwa_add_log($res_id, "ajax_auth: type => \"auth\", user => \"".$user_info->user_login."\"");
                    $user_key = get_user_meta($user_info->ID, 'wwa_user_handle', true);
                    if(!$user_key){
                        $user_id_map = wwa_get_option("user_id");
                        if(is_array($user_id_map) && isset($user_id_map[$user_info->user_login])){
                            $user_key = $user_id_map[$user_info->user_login];
                        }else{
                            wwa_add_log($res_id, "ajax_auth: User found but not initialized, create a fake id");
                            $user_key = hash("sha256", $wwa_get["user"]."-".$wwa_get["user"]."-".wwa_generate_random_string(10));
                            $user_exist = false;
                        }
                    }
                }else{
                    $user_info = new stdClass();
                    $user_info->user_login = $wwa_get["user"];
                    $user_info->display_name = $wwa_get["user"];
                    $user_key = hash("sha256", $wwa_get["user"]."-".$wwa_get["user"]."-".wwa_generate_random_string(10));
                    wwa_add_log($res_id, "ajax_auth: User not exists, create a fake id");
                    wwa_add_log($res_id, "ajax_auth: type => \"auth\", user => \"".$wwa_get["user"]."\"");
                    $user_exist = false;
                }
            }else{
                if(wwa_get_option("usernameless_login") === "true"){
                    $usernameless_flag = true;
                    wwa_add_log($res_id, "ajax_auth: Empty username, try usernameless authentication");
                }else{
                    wwa_add_log($res_id, "ajax_auth: (ERROR)Missing parameters, exit");
                    wwa_wp_die("Bad Request.", $client_id);
                }
            }
        }

        if(!$usernameless_flag){
            $userEntity = new PublicKeyCredentialUserEntity(
                $user_info->user_login,
                $user_key,
                $user_info->display_name,
                $user_icon
            );
        }

        $credentialSourceRepository = new PublicKeyCredentialSourceRepository();
        $rpEntity = new PublicKeyCredentialRpEntity(
            wwa_get_option("website_name"),
            wwa_get_option("website_domain")
        );

        $server = new Server(
            $rpEntity,
            $credentialSourceRepository,
            null
        );

        if($usernameless_flag){
            // Usernameless authentication, return empty allowed credentials list
            wwa_add_log($res_id, "ajax_auth: Usernameless authentication, allowedCredentials => []");
            $allowedCredentials = array();
        }else if(!$user_exist){
            // User doesn't exist or hasn't bound any authenticator,
            // generate deterministic fake credentials
            $fake_seed = hash_hmac('sha256', $user_info->user_login, wp_salt('auth'), true);

            // Determine count: 0 => 25%, 1-5 => 15% each
            $fake_count = ord($fake_seed[0]) % 20;
            $fake_count = $fake_count < 5 ? 0 : intdiv($fake_count - 5, 3) + 1;

            $allowedCredentials = array();
            $id_length_ranges = [[16, 20], [32, 48], [48, 64], [64, 80], [20, 32]];
            for($i = 0; $i < $fake_count; $i++){
                $cred_seed = hash_hmac('sha512', $user_info->user_login . chr($i), wp_salt('auth'), true);
                $range = $id_length_ranges[ord($cred_seed[0]) % count($id_length_ranges)];
                $id_len = $range[0] + (ord($cred_seed[1]) % ($range[1] - $range[0] + 1));
                // Use remaining bytes as credential ID, extend if needed for longer IDs
                $id_bytes = substr($cred_seed, 2);
                if(strlen($id_bytes) < $id_len){
                    $id_bytes .= hash_hmac('sha256', $cred_seed, wp_salt('auth'), true);
                }
                $allowedCredentials[] = new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    substr($id_bytes, 0, $id_len)
                );
            }
            wwa_add_log($res_id, "ajax_auth: User not exists, fake allowedCredentials count => ".$fake_count);
        }else{
            // Get the list of authenticators associated to the user
            $allow_authenticator_type = wwa_get_option("allow_authenticator_type");
            if($allow_authenticator_type === false || $allow_authenticator_type === "none"){
                $credentialSources = $credentialSourceRepository->findAllForUserEntityByUserId($user_info->ID);
            }else{
                wwa_add_log($res_id, "ajax_auth: allow_authenticator_type => \"".$allow_authenticator_type."\", filter authenticators");
                $credentialSources = $credentialSourceRepository->findCredentialsForUserEntityByType($user_info->ID, $allow_authenticator_type);
            }

            // Logged in and testing, if the user haven't bind a authenticator yet, exit
            if(count($credentialSources) === 0 && $wwa_get["type"] === "test" && current_user_can("read")){
                wwa_add_log($res_id, "ajax_auth: (ERROR)No authenticator, exit");
                wwa_wp_die("User not inited.", $client_id);
            }

            // Convert the Credential Sources into Public Key Credential Descriptors for excluding
            $allowedCredentials = array_map(function(PublicKeyCredentialSource $credential){
                return $credential->getPublicKeyCredentialDescriptor();
            }, $credentialSources);

            wwa_add_log($res_id, "ajax_auth: allowedCredentials => ".wp_json_encode($allowedCredentials));
        }

        // Set user verification
        if(wwa_get_option("user_verification") === "true"){
            wwa_add_log($res_id, "ajax_auth: user_verification => \"true\"");
            $user_verification = AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED;
        }else{
            wwa_add_log($res_id, "ajax_auth: user_verification => \"false\"");
            $user_verification = AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
        }

        if($usernameless_flag){
            wwa_add_log($res_id, "ajax_auth: Usernameless authentication, user_verification => \"true\"");
            $user_verification = AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED;
        }

        // Create a auth challenge
        $publicKeyCredentialRequestOptions = $server->generatePublicKeyCredentialRequestOptions(
            $user_verification,
            $allowedCredentials
        );

        // Save for future use
        wwa_set_temp_val("pkcco_auth", base64_encode(serialize($publicKeyCredentialRequestOptions)), $client_id);
        wwa_set_temp_val("auth_type", $wwa_get["type"], $client_id);
        wwa_set_temp_val("user_exist", $user_exist, $client_id);
        if(!$usernameless_flag){
            wwa_set_temp_val("user_name_auth", $user_info->user_login, $client_id);
        }
        wwa_set_temp_val("usernameless_auth", serialize($usernameless_flag), $client_id);

        // Save the user entity if is not logged in and not usernameless
        if(!($wwa_get["type"] === "test" && current_user_can("read")) && !$usernameless_flag){
            wwa_set_temp_val("user_auth", serialize($userEntity), $client_id);
        }

        header("Content-Type: application/json");
        $publicKeyCredentialRequestOptions = json_decode(wp_json_encode($publicKeyCredentialRequestOptions), true);
        $publicKeyCredentialRequestOptions["clientID"] = $client_id;
        echo wp_json_encode($publicKeyCredentialRequestOptions);
        wwa_add_log($res_id, "ajax_auth: Challenge sent");
        exit;
    }catch(\Exception $exception){
        wwa_add_log($res_id, "ajax_auth: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($exception));
        wwa_add_log($res_id, "ajax_auth: (ERROR)Unknown error, exit");
        wwa_wp_die("Something went wrong.", $client_id);
    }catch(\Error $error){
        wwa_add_log($res_id, "ajax_auth: (ERROR)".$error->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($error));
        wwa_add_log($res_id, "ajax_auth: (ERROR)Unknown error, exit");
        wwa_wp_die("Something went wrong.", $client_id);
    }
}
add_action("wp_ajax_wwa_auth_start" , "wwa_ajax_auth_start");
add_action("wp_ajax_nopriv_wwa_auth_start" , "wwa_ajax_auth_start");

function wwa_ajax_auth(){
    $client_id = false;
    try{
        $res_id = wwa_generate_random_string(5);

        wwa_init_new_options();

        $is_conditional = isset($_POST['conditional']) && $_POST['conditional'] === 'true';
        wwa_add_log($res_id, "ajax_auth_response: Client response received" . ($is_conditional ? " (conditional)" : ""));

        if(!isset($_POST["clientid"])){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Missing parameters, exit");
            wp_die("Bad Request.");
        }else{
            // Sanitize the input
            $post_client_id = sanitize_text_field(wp_unslash($_POST["clientid"]));
            if(strlen($post_client_id) < 34 || strlen($post_client_id) > 35){
                wwa_add_log($res_id, "ajax_auth_response: (ERROR)Wrong client ID, exit");
                wwa_wp_die("Bad Request.", $client_id);
            }
            $client_id = $post_client_id;
        }

        // Check POST
        if(!isset($_POST["type"]) || !isset($_POST["data"]) || !isset($_POST["remember"])){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Missing parameters, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }else{
            // Sanitize the input
            $wwa_post = array();
            $wwa_post["type"] = sanitize_text_field(wp_unslash($_POST["type"]));
            $wwa_post["remember"] = sanitize_text_field(wp_unslash($_POST["remember"]));
        }

        $temp_val = array(
            "pkcco_auth" => wwa_get_temp_val("pkcco_auth", $client_id),
            "auth_type" => wwa_get_temp_val("auth_type", $client_id),
            "usernameless_auth" => wwa_get_temp_val("usernameless_auth", $client_id),
            "user_auth" => wwa_get_temp_val("user_auth", $client_id),
            "user_name_auth" => wwa_get_temp_val("user_name_auth", $client_id),
            "user_exist" => wwa_get_temp_val("user_exist", $client_id),
        );

        if($temp_val["auth_type"] === false || $wwa_post["type"] !== $temp_val["auth_type"]){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Wrong parameters, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }

        // Check remember me
        if($wwa_post["remember"] !== "true" && $wwa_post["remember"] !== "false"){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Wrong parameters, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }elseif(wwa_get_option("remember_me") !== "true" && $wwa_post["remember"] === "true"){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Wrong parameters, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }

        // May not get the challenge yet
        if($temp_val["pkcco_auth"] === false || $temp_val["usernameless_auth"] === false || ($wwa_post["type"] !== "test" && $wwa_post["type"] !== "auth")){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Challenge not found in transient, exit");
            wwa_wp_die("Bad request.", $client_id);
        }

        $temp_val["usernameless_auth"] = unserialize($temp_val["usernameless_auth"], ['allowed_classes' => false]);

        if($temp_val["usernameless_auth"] === false && $temp_val["user_name_auth"] === false){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Username not found in transient, exit");
            wwa_wp_die("Bad request.", $client_id);
        }
        if($wwa_post["type"] === "test" && !current_user_can("read")){
            // Test but not logged in
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Permission denied, exit");
            wwa_wp_die("Bad request.", $client_id);
        }
        if(!($wwa_post["type"] === "test" && current_user_can("read")) && ($temp_val["usernameless_auth"] === false && $temp_val["user_auth"] === false)){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Permission denied, exit");
            wwa_wp_die("Bad request.", $client_id);
        }

        $usernameless_flag = $temp_val["usernameless_auth"];

        $psr17Factory = new Psr17Factory();
        $creator = new ServerRequestCreator(
            $psr17Factory,
            $psr17Factory,
            $psr17Factory,
            $psr17Factory
        );

        $serverRequest = $creator->fromGlobals();
        $publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();

        // If user entity is not saved, read from WordPress
        $user_key = "";
        if($wwa_post["type"] === "test" && current_user_can('read') && !$usernameless_flag){
            $user_info = wp_get_current_user();

            if(isset($_POST["user_id"])){
                $user_id = intval(sanitize_text_field(wp_unslash($_POST["user_id"])));
                if($user_id <= 0){
                    wwa_add_log($res_id, "ajax_auth_response: (ERROR)Wrong parameters, exit");
                    wwa_wp_die("Bad Request.");
                }

                if($user_info->ID !== $user_id){
                    if(!current_user_can("edit_user", $user_id)){
                        wwa_add_log($res_id, "ajax_auth_response: (ERROR)No permission, exit");
                        wwa_wp_die("Something went wrong.");
                    }
                    $user_info = get_user_by('id', $user_id);

                    if($user_info === false){
                        wwa_add_log($res_id, "ajax_auth_response: (ERROR)Wrong user ID, exit");
                        wwa_wp_die("Something went wrong.");
                    }
                }
            }

            $user_key = get_user_meta($user_info->ID, 'wwa_user_handle', true);
            if(!$user_key){
                $user_id_map = wwa_get_option("user_id");
                if(is_array($user_id_map) && isset($user_id_map[$user_info->user_login])){
                    $user_key = $user_id_map[$user_info->user_login];
                }else{
                    wwa_add_log($res_id, "ajax_auth_response: (ERROR)User not initialized, exit");
                    wwa_wp_die("User not inited.", $client_id);
                }
            }
            $user_icon = get_avatar_url($user_info->user_email, array("scheme" => "https"));

            $userEntity = new PublicKeyCredentialUserEntity(
                $user_info->user_login,
                $user_key,
                $user_info->display_name,
                $user_icon
            );

            wwa_add_log($res_id, "ajax_auth_response: type => \"test\", user => \"".$user_info->user_login."\"");
        }else{
            if($usernameless_flag){
                $data_array = json_decode(base64_decode(sanitize_text_field(wp_unslash($_POST["data"]))), true);
                if(!isset($data_array["response"]["userHandle"]) || !isset($data_array["rawId"])){
                    wwa_add_log($res_id, "ajax_auth_response: (ERROR)Client data not correct, exit");
                    wwa_wp_die("Bad request.", $client_id);
                }

                wwa_add_log($res_id, "ajax_auth_response: type => \"".$wwa_post["type"]."\"");
                wwa_add_log($res_id, "ajax_auth_response: Usernameless authentication, try to find user by credential_id => \"".sanitize_text_field($data_array["rawId"])."\"");

                $credential_meta = $publicKeyCredentialSourceRepository->findOneMetaByCredentialId(base64_decode($data_array["rawId"]));

                if($credential_meta !== null){
                    $allow_authenticator_type = wwa_get_option("allow_authenticator_type");
                    if($allow_authenticator_type !== false && $allow_authenticator_type !== 'none'){
                        if($credential_meta["authenticator_type"] !== $allow_authenticator_type){
                            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Credential type error, exit");
                            wwa_wp_die("Bad request.", $client_id);
                        }
                    }
                    if($credential_meta["usernameless"] === true){
                        global $wpdb;
                        $cred_row = $wpdb->get_row($wpdb->prepare(
                            "SELECT user_id, user_handle FROM {$wpdb->wwa_credentials} WHERE credential_id = %s",
                            base64_encode(base64_decode($data_array["rawId"]))
                        ));

                        $resolved_user_handle = null;
                        $resolved_user_info = null;

                        if($cred_row !== null){
                            $resolved_user_handle = $cred_row->user_handle;
                            $resolved_user_info = get_user_by('id', $cred_row->user_id);
                        }elseif(!get_option('wwa_credentials_migrated')){
                            wwa_add_log($res_id, "ajax_auth_response: Credential not in global table, trying pre-migration fallback");
                            $old_handle = $credential_meta["user"];
                            $all_user = wwa_get_option("user_id");
                            if(is_array($all_user)){
                                foreach($all_user as $login => $handle){
                                    if($handle === $old_handle){
                                        $resolved_user_info = get_user_by('login', $login);
                                        $resolved_user_handle = $old_handle;
                                        break;
                                    }
                                }
                            }
                        }

                        if($resolved_user_info === false || $resolved_user_info === null){
                            wwa_add_log($res_id, "ajax_auth_response: (ERROR)User not found, exit");
                            wwa_wp_die("Bad request.", $client_id);
                        }

                        if($resolved_user_handle !== base64_decode($data_array["response"]["userHandle"])){
                            wwa_add_log($res_id, "ajax_auth_response: (ERROR)userHandle not matched, exit");
                            wwa_wp_die("Bad request.", $client_id);
                        }

                        $user_info = $resolved_user_info;
                        $user_login_name = $user_info->user_login;
                        wwa_add_log($res_id, "ajax_auth_response: Found user => \"".$user_login_name."\"");

                        if($wwa_post["type"] === "test" && current_user_can('read')){
                            $user_wp = wp_get_current_user();
                            if($user_login_name !== $user_wp->user_login){
                                wwa_add_log($res_id, "ajax_auth_response: (ERROR)User not match, exit");
                                wwa_wp_die("Bad request.", $client_id);
                            }
                        }

                        $userEntity = new PublicKeyCredentialUserEntity(
                            $user_info->user_login,
                            $resolved_user_handle,
                            $user_info->display_name,
                            get_avatar_url($user_info->user_email, array("scheme" => "https"))
                        );
                    }else{
                        wwa_add_log($res_id, "ajax_auth_response: (ERROR)Credential found, but usernameless => \"false\", exit");
                        wwa_wp_die("Bad request.", $client_id);
                    }
                }else{
                    wwa_add_log($res_id, "ajax_auth_response: (ERROR)Credential not found, exit");
                    wwa_wp_die("Bad request.", $client_id);
                }
            }else{
                wwa_add_log($res_id, "ajax_auth_response: type => \"auth\", user => \"".$temp_val["user_name_auth"]."\"");
                $userEntity = unserialize($temp_val["user_auth"], ['allowed_classes' => [
                    Webauthn\PublicKeyCredentialUserEntity::class,
                ]]);
            }
        }

        $decoded_data = base64_decode(sanitize_text_field(wp_unslash($_POST["data"])));
        wwa_add_log($res_id, "ajax_auth_response: data => ".sanitize_text_field($decoded_data));

        if($temp_val["user_exist"]){
            $rpEntity = new PublicKeyCredentialRpEntity(
                wwa_get_option("website_name"),
                wwa_get_option("website_domain")
            );

            $server = new Server(
                $rpEntity,
                $publicKeyCredentialSourceRepository,
                null
            );

            // Allow to bypass scheme verification when under localhost
            $current_domain = wwa_get_option("website_domain");
            if($current_domain === "localhost" || $current_domain === "127.0.0.1"){
                $server->setSecuredRelyingPartyId([$current_domain]);
                wwa_add_log($res_id, "ajax_auth_response: Localhost, bypass HTTPS check");
            }

            // Verify
            try {
                $server->loadAndCheckAssertionResponse(
                    $decoded_data,
                    unserialize(base64_decode($temp_val["pkcco_auth"]), ['allowed_classes' => [
                        Webauthn\PublicKeyCredentialRequestOptions::class,
                        Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs::class,
                        Webauthn\PublicKeyCredentialDescriptor::class,
                    ]]),
                    $userEntity,
                    $serverRequest
                );

                wwa_add_log($res_id, "ajax_auth_response: Challenge verified");

                // Success
                $publicKeyCredentialSourceRepository->updateCredentialLastUsed(base64_decode(json_decode($decoded_data, true)["rawId"]));
                if(!($wwa_post["type"] === "test" && current_user_can("read"))){
                    // Log user in
                    if (!is_user_logged_in()) {
                        include("wwa-compatibility.php");

                        if(!$usernameless_flag){
                            $user_login = $temp_val["user_name_auth"];
                        }else{
                            $user_login = $user_login_name;
                        }

                        $user = get_user_by("login", $user_login);

                        if($user === false){
                            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Wrong user ID, exit");
                            wwa_wp_die("Something went wrong.");
                        }

                        $user_id = $user->ID;

                        wwa_add_log($res_id, "ajax_auth_response: Log in user => \"".$user_login."\"");

                        $remember_flag = false;

                        if ($wwa_post["remember"] === "true" && (wwa_get_option("remember_me") === false ? "false" : wwa_get_option("remember_me")) !== "false") {
                            $remember_flag = true;
                            wwa_add_log($res_id, "ajax_auth_response: Remember login for 14 days");
                        }

                        wp_set_current_user($user_id, $user_login);
                        if(isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] === "on"){
                            wp_set_auth_cookie($user_id, $remember_flag, true);
                        }else{
                            wp_set_auth_cookie($user_id, $remember_flag);
                        }
                        do_action("wp_login", $user_login, $user);
                    }
                }
                echo "true";
            }catch(\Throwable $exception){
                // Failed to verify
                wwa_add_log($res_id, "ajax_auth_response: (ERROR)".$exception->getMessage());
                wwa_add_log($res_id, wwa_generate_call_trace($exception));
                wwa_add_log($res_id, "ajax_auth_response: (ERROR)Challenge not verified, exit");
                wwa_wp_die("Something went wrong.", $client_id);
            }
        }else{
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)User not exists or has no authenticator, exit without verification");
            wwa_wp_die("Something went wrong.", $client_id);
        }

        // Destroy session
        wwa_destroy_temp_val($client_id);
        exit;
    }catch(\Exception $exception){
        wwa_add_log($res_id, "ajax_auth_response: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($exception));
        wwa_add_log($res_id, "ajax_auth_response: (ERROR)Unknown error, exit");
        wwa_wp_die("Something went wrong.", $client_id);
    }catch(\Error $error){
        wwa_add_log($res_id, "ajax_auth_response: (ERROR)".$error->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($error));
        wwa_add_log($res_id, "ajax_auth_response: (ERROR)Unknown error, exit");
        wwa_wp_die("Something went wrong.", $client_id);
    }
}
add_action("wp_ajax_wwa_auth" , "wwa_ajax_auth");
add_action("wp_ajax_nopriv_wwa_auth" , "wwa_ajax_auth");

// Get authenticator list
function wwa_ajax_authenticator_list(){
    check_ajax_referer('wwa_ajax');
    $res_id = wwa_generate_random_string(5);

    wwa_init_new_options();

    if(!current_user_can("read")){
        wwa_add_log($res_id, "ajax_authenticator_list: (ERROR)Missing parameters, exit");
        wwa_wp_die("Something went wrong.");
    }

    $user_info = wp_get_current_user();

    if(isset($_GET["user_id"])){
        $user_id = intval(sanitize_text_field(wp_unslash($_GET["user_id"])));
        if($user_id <= 0){
            wwa_add_log($res_id, "ajax_authenticator_list: (ERROR)Wrong parameters, exit");
            wwa_wp_die("Bad Request.");
        }

        if($user_info->ID !== $user_id){
            if(!current_user_can("edit_user", $user_id)){
                wwa_add_log($res_id, "ajax_authenticator_list: (ERROR)No permission, exit");
                wwa_wp_die("Something went wrong.");
            }
            $user_info = get_user_by('id', $user_id);

            if($user_info === false){
                wwa_add_log($res_id, "ajax_authenticator_list: (ERROR)Wrong user ID, exit");
                wwa_wp_die("Something went wrong.");
            }
        }
    }

    header('Content-Type: application/json');

    $user_key = get_user_meta($user_info->ID, 'wwa_user_handle', true);
    if(!$user_key){
        echo "[]";
        exit;
    }

    $publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();
    echo wp_json_encode($publicKeyCredentialSourceRepository->getShowListByUserId($user_info->ID));
    exit;
}
add_action("wp_ajax_wwa_authenticator_list" , "wwa_ajax_authenticator_list");

// Modify an authenticator
function wwa_ajax_modify_authenticator(){
    check_ajax_referer('wwa_ajax');
    try{
        $res_id = wwa_generate_random_string(5);

        wwa_init_new_options();

        wwa_add_log($res_id, "ajax_modify_authenticator: Start");

        if(!current_user_can("read")){
            wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Permission denied, exit");
            wwa_wp_die("Bad Request.");
        }

        if(!isset($_GET["id"]) || !isset($_GET["target"])){
            wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Missing parameters, exit");
            wwa_wp_die("Bad Request.");
        }

        $user_info = wp_get_current_user();

        if(isset($_GET["user_id"])){
            $user_id = intval(sanitize_text_field(wp_unslash($_GET["user_id"])));
            if($user_id <= 0){
                wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Wrong parameters, exit");
                wwa_wp_die("Bad Request.");
            }

            if($user_info->ID !== $user_id){
                if(!current_user_can("edit_user", $user_id)){
                    wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)No permission, exit");
                    wwa_wp_die("Something went wrong.");
                }
                $user_info = get_user_by('id', $user_id);

                if($user_info === false){
                    wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Wrong user ID, exit");
                    wwa_wp_die("Something went wrong.");
                }
            }
        }

        if($_GET["target"] !== "rename" && $_GET["target"] !== "remove"){
            wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Wrong target, exit");
            wwa_wp_die("Bad Request.");
        }

        if($_GET["target"] === "rename" && !isset($_GET["name"])){
            wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Missing parameters, exit");
            wwa_wp_die("Bad Request.");
        }

        wwa_add_log($res_id, "ajax_modify_authenticator: user => \"".$user_info->user_login."\"");

        $publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();

        if($_GET["target"] === "rename"){
            $result = $publicKeyCredentialSourceRepository->renameCredential(
                sanitize_text_field(wp_unslash($_GET["id"])),
                $user_info->ID,
                sanitize_text_field(wp_unslash($_GET["name"])),
                $res_id
            );
            echo $result ? "true" : "Not Found.";
        }elseif($_GET["target"] === "remove"){
            $result = $publicKeyCredentialSourceRepository->removeCredential(
                sanitize_text_field(wp_unslash($_GET["id"])),
                $user_info->ID,
                $res_id
            );
            echo $result ? "true" : "Not Found.";
        }
        exit;
    }catch(\Exception $exception){
        wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($exception));
        wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Unknown error, exit");
        wwa_wp_die("Something went wrong.");
    }catch(\Error $error){
        wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)".$error->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($error));
        wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Unknown error, exit");
        wwa_wp_die("Something went wrong.");
    }
}
add_action("wp_ajax_wwa_modify_authenticator" , "wwa_ajax_modify_authenticator");

// Print log
function wwa_ajax_get_log(){
    check_ajax_referer('wwa_admin_ajax');
    if(!wwa_validate_privileges()){
        wwa_wp_die("Bad Request.");
    }

    header('Content-Type: application/json');

    $log = get_option("wwa_log");

    if($log === false){
        echo "[]";
    }else{
        echo wp_json_encode($log);
    }

    exit;
}
add_action("wp_ajax_wwa_get_log" , "wwa_ajax_get_log");

// Clear log
function wwa_ajax_clear_log(){
    check_ajax_referer('wwa_admin_ajax');
    if(!wwa_validate_privileges()){
        wwa_wp_die("Bad Request.");
    }

    $log = get_option("wwa_log");

    if($log !== false){
        update_option("wwa_log", array());
    }

    echo "true";
    exit;
}
add_action("wp_ajax_wwa_clear_log" , "wwa_ajax_clear_log");
