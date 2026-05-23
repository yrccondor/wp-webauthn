<?php
if (!defined('ABSPATH')) {
    exit;
}

require_once('wp-webauthn-vendor/autoload.php');
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredential;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAssertionResponse;

function wwa_unserialize_creation_options($stored_options): ?PublicKeyCredentialCreationOptions {
    if(!is_string($stored_options) || $stored_options === ''){
        return null;
    }

    $serialized = base64_decode($stored_options, true);
    if(!is_string($serialized) || $serialized === ''){
        return null;
    }

    $options = @unserialize($serialized, ['allowed_classes' => [
        Webauthn\PublicKeyCredentialCreationOptions::class,
        Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs::class,
        Webauthn\AuthenticationExtensions\AuthenticationExtensions::class,
        Webauthn\PublicKeyCredentialRpEntity::class,
        Webauthn\PublicKeyCredentialUserEntity::class,
        Webauthn\AuthenticatorSelectionCriteria::class,
        Webauthn\PublicKeyCredentialParameters::class,
        Webauthn\PublicKeyCredentialDescriptor::class,
    ]]);

    return $options instanceof PublicKeyCredentialCreationOptions ? $options : null;
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

        $rp_id = wwa_get_rp_id();
        if($rp_id === ''){
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

        $rpEntity = wwa_get_rp_entity($rp_id);

        wwa_add_log($res_id, "ajax_create: user => \"".$user_info->user_login."\"");

        $user_key = wwa_get_or_create_user_handle($user_info, $res_id);
        $userEntity = wwa_get_user_entity($user_info, $user_key);

        $credentialRecordRepository = new CredentialRecordRepository();
        $excludeCredentials = $credentialRecordRepository->findCredentialDescriptorsForUserId($user_info->ID);

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
        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create(
            authenticatorAttachment: $authenticator_type,
            userVerification: $user_verification,
            residentKey: $resident_key
                ? AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED
                : AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_DISCOURAGED
        );

        // Create a creation challenge
        $managers = wwa_get_webauthn_support_managers();
        $pubKeyCredParams = array_map(
            fn(int $id) => PublicKeyCredentialParameters::createPk($id),
            iterator_to_array($managers['algorithmManager']->list())
        );

        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::create(
            $rpEntity,
            $userEntity,
            random_bytes(32),
            pubKeyCredParams: $pubKeyCredParams,
            authenticatorSelection: $authenticatorSelectionCriteria,
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            excludeCredentials: $excludeCredentials,
            hints: wwa_get_public_key_hints($wwa_get["type"])
        );

        // Save for future use
        wwa_set_temp_val("pkcco", base64_encode(serialize($publicKeyCredentialCreationOptions)), $client_id);
        wwa_set_temp_val("bind_config", array(
            "name" => $wwa_get["name"],
            "type" => $wwa_get["type"],
            "usernameless" => $resident_key,
            "user_id" => intval($user_info->ID),
            "user_handle" => $user_key,
        ), $client_id);

        // Use serializer to produce spec-compliant JSON (base64url, etc.)
        $components = wwa_get_server_components($rp_id);
        $challenge_json = $components['serializer']->serialize($publicKeyCredentialCreationOptions, 'json', [
            'json_encode_options' => JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ]);
        $challenge_array = json_decode($challenge_json, true);
        if(!is_array($challenge_array)){
            throw new \RuntimeException("Failed to encode creation options");
        }
        $challenge_array["clientID"] = $client_id;

        header("Content-Type: application/json");
        echo wp_json_encode($challenge_array);
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
        if(!is_array($temp_val["bind_config"]) || !isset($temp_val["bind_config"]["type"], $temp_val["bind_config"]["name"], $temp_val["bind_config"]["usernameless"], $temp_val["bind_config"]["user_id"], $temp_val["bind_config"]["user_handle"])){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Challenge config invalid, exit");
            wwa_wp_die("Bad request.", $client_id);
        }

        $bound_user_id = intval($temp_val["bind_config"]["user_id"]);
        $bound_user_handle = strval($temp_val["bind_config"]["user_handle"]);
        if($bound_user_id <= 0 || $bound_user_handle === ""){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Challenge user binding invalid, exit");
            wwa_wp_die("Bad request.", $client_id);
        }

        if(isset($_POST["user_id"])){
            $posted_user_id = intval(sanitize_text_field(wp_unslash($_POST["user_id"])));
            if($posted_user_id <= 0 || $posted_user_id !== $bound_user_id){
                wwa_add_log($res_id, "ajax_create_response: (ERROR)Challenge user mismatch, exit");
                wwa_wp_die("Bad Request.", $client_id);
            }
        }

        $current_user = wp_get_current_user();
        if(intval($current_user->ID) !== $bound_user_id && !current_user_can("edit_user", $bound_user_id)){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)No permission for challenged user, exit");
            wwa_wp_die("Something went wrong.", $client_id);
        }

        $user_info = get_user_by('id', $bound_user_id);
        if($user_info === false){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Challenged user not found, exit");
            wwa_wp_die("Something went wrong.", $client_id);
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
        $decoded_credential_payload = wwa_decode_client_credential_payload($_POST["data"]);
        if($decoded_credential_payload === null){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Client data not correct, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }
        wwa_add_log($res_id, "ajax_create_response: data => ".sanitize_text_field($decoded_credential_payload['json']));

        // Check global unique credential ID
        $credential_id = $decoded_credential_payload['raw_id'];
        $credentialRecordRepository = new CredentialRecordRepository();
        if($credentialRecordRepository->findOneMetaByCredentialId($credential_id) !== null){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Credential ID not unique, ID => \"".base64_encode($credential_id)."\" , exit");
            wwa_wp_die("Something went wrong.", $client_id);
        }else{
            wwa_add_log($res_id, "ajax_create_response: Credential ID unique check passed");
        }

        $rp_id = wwa_get_rp_id();
        if($rp_id === ''){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Plugin not configured, exit");
            wwa_wp_die("Not configured.", $client_id);
        }
        $components = wwa_get_server_components($rp_id);

        // Verify
        try {
            $publicKeyCredential = $components['serializer']->deserialize(
                wwa_normalize_credential_response($decoded_credential_payload['json']),
                PublicKeyCredential::class,
                'json'
            );

            if(!$publicKeyCredential->response instanceof AuthenticatorAttestationResponse){
                throw new \RuntimeException("Invalid response type");
            }

            $publicKeyCredentialCreationOptions = wwa_unserialize_creation_options($temp_val["pkcco"]);
            if(!$publicKeyCredentialCreationOptions instanceof PublicKeyCredentialCreationOptions){
                wwa_add_log($res_id, "ajax_create_response: (ERROR)Challenge not found in transient, exit");
                wwa_wp_die("Bad request.", $client_id);
            }
            if(!hash_equals($bound_user_handle, $publicKeyCredentialCreationOptions->user->id)){
                wwa_add_log($res_id, "ajax_create_response: (ERROR)Challenge user handle mismatch, exit");
                wwa_wp_die("Bad request.", $client_id);
            }

            $credentialRecord = $components['attestationValidator']->check(
                $publicKeyCredential->response,
                $publicKeyCredentialCreationOptions,
                wwa_get_current_site_host()
            );
            if(!hash_equals($bound_user_handle, $credentialRecord->userHandle)){
                wwa_add_log($res_id, "ajax_create_response: (ERROR)Credential user handle mismatch, exit");
                wwa_wp_die("Bad request.", $client_id);
            }

            wwa_add_log($res_id, "ajax_create_response: Challenge verified");

            $credentialRecordRepository->setRegistrationContext(
                $user_info->ID,
                $wwa_post["name"],
                $wwa_post["type"],
                $temp_val["bind_config"]["usernameless"]
            );
            $credentialRecordRepository->saveCredentialRecord($credentialRecord);

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

function wwa_ajax_conditional_create_start(){
    check_ajax_referer('wwa_ajax');
    $client_id = false;
    $res_id = '-----';
    try{
        $res_id = wwa_generate_random_string(5);
        $client_id = strval(time()).wwa_generate_random_string(24);

        wwa_init_new_options();
        wwa_add_log($res_id, "ajax_conditional_create: Start");

        if(!current_user_can('read')){
            wwa_add_log($res_id, "ajax_conditional_create: (ERROR)Permission denied, exit");
            wwa_wp_die("Something went wrong.", $client_id);
        }

        $user_info = wp_get_current_user();
        $conditional_create_mode = wwa_get_effective_conditional_create_mode_for_user($user_info->ID);
        if($conditional_create_mode === 'off'){
            wwa_add_log($res_id, "ajax_conditional_create: (ERROR)Conditional Create disabled or user not eligible, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }
        if(!wwa_check_ssl() && !wwa_is_loopback_host(wwa_get_current_site_host())){
            wwa_add_log($res_id, "ajax_conditional_create: (ERROR)Not secure context, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }

        $rp_id = wwa_get_rp_id();
        if($rp_id === ''){
            wwa_add_log($res_id, "ajax_conditional_create: (ERROR)Plugin not configured, exit");
            wwa_wp_die("Not configured.", $client_id);
        }

        $user_key = wwa_get_or_create_user_handle($user_info, $res_id);
        $userEntity = wwa_get_user_entity($user_info, $user_key);
        $rpEntity = wwa_get_rp_entity($rp_id);

        $credentialRecordRepository = new CredentialRecordRepository();
        $excludeCredentials = $conditional_create_mode === 'no-credentials'
            ? array()
            : $credentialRecordRepository->findCredentialDescriptorsForUserId($user_info->ID);

        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create(
            authenticatorAttachment: AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED
        );

        $managers = wwa_get_webauthn_support_managers();
        $pubKeyCredParams = array_map(
            fn(int $id) => PublicKeyCredentialParameters::createPk($id),
            iterator_to_array($managers['algorithmManager']->list())
        );

        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::create(
            $rpEntity,
            $userEntity,
            random_bytes(32),
            pubKeyCredParams: $pubKeyCredParams,
            authenticatorSelection: $authenticatorSelectionCriteria,
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            excludeCredentials: $excludeCredentials,
            hints: wwa_get_public_key_hints('none'),
            mediation: PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL
        );

        wwa_set_temp_val('pkcco_conditional', base64_encode(serialize($publicKeyCredentialCreationOptions)), $client_id);
        wwa_set_temp_val('bind_config_conditional', array(
            'name' => sprintf(__('Passkey created on %s', 'wp-webauthn'), current_time('mysql')),
            'type' => 'none',
            'usernameless' => true,
            'user_id' => intval($user_info->ID),
            'user_handle' => $user_key,
        ), $client_id);

        $components = wwa_get_server_components($rp_id);
        $challenge_json = $components['serializer']->serialize($publicKeyCredentialCreationOptions, 'json', [
            'json_encode_options' => JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ]);
        $challenge_array = json_decode($challenge_json, true);
        if(!is_array($challenge_array)){
            throw new \RuntimeException('Failed to encode conditional creation options');
        }
        $challenge_array['clientID'] = $client_id;

        header('Content-Type: application/json');
        echo wp_json_encode($challenge_array);
        wwa_add_log($res_id, "ajax_conditional_create: Challenge sent");
        exit;
    }catch(\Exception $exception){
        wwa_add_log($res_id, "ajax_conditional_create: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($exception));
        wwa_wp_die("Something went wrong.", $client_id);
    }catch(\Error $error){
        wwa_add_log($res_id, "ajax_conditional_create: (ERROR)".$error->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($error));
        wwa_wp_die("Something went wrong.", $client_id);
    }
}
add_action("wp_ajax_wwa_conditional_create_start", "wwa_ajax_conditional_create_start");

function wwa_ajax_conditional_create_response(){
    check_ajax_referer('wwa_ajax');
    $client_id = false;
    $res_id = '-----';
    try{
        $res_id = wwa_generate_random_string(5);
        wwa_init_new_options();
        wwa_add_log($res_id, "ajax_conditional_create_response: Client response received");

        if(!wwa_is_conditional_create_enabled() || !current_user_can('read')){
            wwa_add_log($res_id, "ajax_conditional_create_response: (ERROR)Permission denied or disabled, exit");
            wwa_wp_die("Bad Request.");
        }
        if(!isset($_POST['clientid']) || !isset($_POST['data'])){
            wwa_add_log($res_id, "ajax_conditional_create_response: (ERROR)Missing parameters, exit");
            wwa_wp_die("Bad Request.");
        }

        $client_id = sanitize_text_field(wp_unslash($_POST['clientid']));
        if(strlen($client_id) < 34 || strlen($client_id) > 35){
            wwa_add_log($res_id, "ajax_conditional_create_response: (ERROR)Wrong client ID, exit");
            wwa_wp_die("Bad Request.", $client_id);
        }

        $temp_val = array(
            'pkcco' => wwa_get_temp_val('pkcco_conditional', $client_id),
            'bind_config' => wwa_get_temp_val('bind_config_conditional', $client_id),
        );
        if($temp_val['pkcco'] === false || $temp_val['bind_config'] === false){
            wwa_add_log($res_id, "ajax_conditional_create_response: (ERROR)Challenge not found in transient, exit");
            wwa_wp_die("Bad request.", $client_id);
        }
        if(!is_array($temp_val['bind_config']) || !isset($temp_val['bind_config']['name'], $temp_val['bind_config']['type'], $temp_val['bind_config']['user_id'], $temp_val['bind_config']['user_handle'])){
            wwa_add_log($res_id, "ajax_conditional_create_response: (ERROR)Challenge config invalid, exit");
            wwa_wp_die("Bad request.", $client_id);
        }

        $bound_user_id = intval($temp_val['bind_config']['user_id']);
        $bound_user_handle = strval($temp_val['bind_config']['user_handle']);
        $user_info = wp_get_current_user();
        if($bound_user_id <= 0 || $bound_user_handle === '' || intval($user_info->ID) !== $bound_user_id){
            wwa_add_log($res_id, "ajax_conditional_create_response: (ERROR)Challenge user mismatch, exit");
            wwa_wp_die("Bad request.", $client_id);
        }

        $decoded_credential_payload = wwa_decode_client_credential_payload($_POST['data']);
        if($decoded_credential_payload === null){
            wwa_add_log($res_id, "ajax_conditional_create_response: (ERROR)Client data not correct, exit");
            wwa_wp_die("Bad request.", $client_id);
        }
        $decoded_data = $decoded_credential_payload['json'];

        $credential_id = $decoded_credential_payload['raw_id'];
        $credentialRecordRepository = new CredentialRecordRepository();
        if($credentialRecordRepository->findOneMetaByCredentialId($credential_id) !== null){
            wwa_add_log($res_id, "ajax_conditional_create_response: (ERROR)Credential ID not unique, exit");
            wwa_wp_die("Something went wrong.", $client_id);
        }

        $rp_id = wwa_get_rp_id();
        if($rp_id === ''){
            wwa_add_log($res_id, "ajax_conditional_create_response: (ERROR)Plugin not configured, exit");
            wwa_wp_die("Not configured.", $client_id);
        }
        $components = wwa_get_server_components($rp_id);

        $publicKeyCredential = $components['serializer']->deserialize(
            wwa_normalize_credential_response($decoded_data),
            PublicKeyCredential::class,
            'json'
        );
        if(!$publicKeyCredential->response instanceof AuthenticatorAttestationResponse){
            throw new \RuntimeException('Invalid response type');
        }

        $publicKeyCredentialCreationOptions = wwa_unserialize_creation_options($temp_val['pkcco']);
        if(!$publicKeyCredentialCreationOptions instanceof PublicKeyCredentialCreationOptions){
            wwa_add_log($res_id, "ajax_conditional_create_response: (ERROR)Challenge not found in transient, exit");
            wwa_wp_die("Bad request.", $client_id);
        }
        if(!hash_equals($bound_user_handle, $publicKeyCredentialCreationOptions->user->id)){
            wwa_add_log($res_id, "ajax_conditional_create_response: (ERROR)Challenge user handle mismatch, exit");
            wwa_wp_die("Bad request.", $client_id);
        }

        $credentialRecord = $components['conditionalAttestationValidator']->check(
            $publicKeyCredential->response,
            $publicKeyCredentialCreationOptions,
            wwa_get_current_site_host()
        );
        if(!hash_equals($bound_user_handle, $credentialRecord->userHandle)){
            wwa_add_log($res_id, "ajax_conditional_create_response: (ERROR)Credential user handle mismatch, exit");
            wwa_wp_die("Bad request.", $client_id);
        }

        $credentialRecordRepository->setRegistrationContext(
            $user_info->ID,
            $temp_val['bind_config']['name'],
            $temp_val['bind_config']['type'],
            true
        );
        $credentialRecordRepository->saveCredentialRecord($credentialRecord);

        $payload = wwa_get_current_user_details_signal_payload($user_info);
        wwa_destroy_temp_val($client_id);
        wp_send_json(array(
            'success' => true,
            'signal' => array(
                'type' => 'currentUserDetails',
                'payload' => $payload,
            ),
        ));
    }catch(\Throwable $exception){
        wwa_add_log($res_id, "ajax_conditional_create_response: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($exception));
        wwa_wp_die("Something went wrong.", $client_id);
    }
}
add_action("wp_ajax_wwa_conditional_create_response", "wwa_ajax_conditional_create_response");

// Auth challenge
function wwa_ajax_auth_start(){
    $client_id = false;
    try{
        $res_id = wwa_generate_random_string(5);
        $client_id = strval(time()).wwa_generate_random_string(24);

        wwa_init_new_options();

        $rp_id = wwa_get_rp_id();
        if($rp_id === ''){
            wwa_add_log($res_id, "ajax_auth: (ERROR)Plugin not configured, exit");
            wwa_auth_json_failure("Not configured.", $client_id, array(), 503);
        }

        $is_conditional = isset($_GET['conditional']) && $_GET['conditional'] === 'true';
        wwa_add_log($res_id, "ajax_auth: Start" . ($is_conditional ? " (conditional)" : ""));

        // Check queries
        if(!isset($_GET["type"])){
            wwa_add_log($res_id, "ajax_auth: (ERROR)Missing parameters, exit");
            wwa_auth_json_failure("Bad Request.", $client_id);
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
                    wwa_auth_json_failure("Bad Request.", $client_id);
                }
            }
        }

        if($wwa_get["type"] === "test" && !current_user_can('read')){
            // Test but not logged in
            wwa_add_log($res_id, "ajax_auth: (ERROR)Permission denied, exit");
            wwa_auth_json_failure("Bad request.", $client_id, array(), 403);
        }

        $user_key = "";
        $usernameless_flag = false;
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
                            wwa_auth_json_failure("Bad Request.", $client_id);
                        }

                        if($user_info->ID !== $user_id){
                            if(!current_user_can("edit_user", $user_id)){
                                wwa_add_log($res_id, "ajax_auth: (ERROR)No permission, exit");
                                wwa_auth_json_failure("Something went wrong.", $client_id, array(), 403);
                            }
                            $user_info = get_user_by('id', $user_id);

                            if($user_info === false){
                                wwa_add_log($res_id, "ajax_auth: (ERROR)Wrong user ID, exit");
                                wwa_auth_json_failure("Something went wrong.", $client_id);
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
                            wwa_auth_json_failure("User not inited.", $client_id);
                        }
                    }
                }else{
                    if(wwa_get_option("usernameless_login") === "true"){
                        wwa_add_log($res_id, "ajax_auth: type => \"test\", usernameless => \"true\"");
                        $usernameless_flag = true;
                    }else{
                        wwa_add_log($res_id, "ajax_auth: (ERROR)Wrong parameters, exit");
                        wwa_auth_json_failure("Bad Request.", $client_id);
                    }
                }
            }else{
                wwa_add_log($res_id, "ajax_auth: (ERROR)Missing parameters, exit");
                wwa_auth_json_failure("Bad Request.", $client_id);
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
                    wwa_auth_json_failure("Bad Request.", $client_id);
                }
            }
        }

        if(!$usernameless_flag){
            $userEntity = wwa_get_user_entity($user_info, $user_key);
        }

        $credentialRecordRepository = new CredentialRecordRepository();

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
                $allowedCredentials[] = PublicKeyCredentialDescriptor::create(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    substr($id_bytes, 0, $id_len)
                );
            }
            wwa_add_log($res_id, "ajax_auth: User not exists, fake allowedCredentials count => ".$fake_count);
        }else{
            // Get the list of authenticators associated to the user
            $allow_authenticator_type = wwa_get_option("allow_authenticator_type");
            if($allow_authenticator_type === false || $allow_authenticator_type === "none"){
                $allowedCredentials = $credentialRecordRepository->findCredentialDescriptorsForUserId($user_info->ID);
            }else{
                wwa_add_log($res_id, "ajax_auth: allow_authenticator_type => \"".$allow_authenticator_type."\", filter authenticators");
                $allowedCredentials = $credentialRecordRepository->findCredentialDescriptorsForUserId($user_info->ID, $allow_authenticator_type);
            }

            // Logged in and testing, if the user haven't bind a authenticator yet, exit
            if(count($allowedCredentials) === 0 && $wwa_get["type"] === "test" && current_user_can("read")){
                wwa_add_log($res_id, "ajax_auth: (ERROR)No authenticator, exit");
                wwa_auth_json_failure("User not inited.", $client_id);
            }

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
        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
            random_bytes(32),
            rpId: $rp_id,
            allowCredentials: $allowedCredentials,
            userVerification: $user_verification,
            hints: wwa_get_public_key_hints(wwa_get_option("allow_authenticator_type") === false ? 'none' : wwa_get_option("allow_authenticator_type"))
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

        // Use serializer to produce spec-compliant JSON
        $components = wwa_get_server_components($rp_id);
        $challenge_json = $components['serializer']->serialize($publicKeyCredentialRequestOptions, 'json', [
            'json_encode_options' => JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ]);
        $challenge_array = json_decode($challenge_json, true);
        if(!is_array($challenge_array)){
            throw new \RuntimeException("Failed to encode request options");
        }
        $challenge_array["clientID"] = $client_id;

        header("Content-Type: application/json");
        echo wp_json_encode($challenge_array);
        wwa_add_log($res_id, "ajax_auth: Challenge sent");
        exit;
    }catch(\Exception $exception){
        wwa_add_log($res_id, "ajax_auth: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($exception));
        wwa_add_log($res_id, "ajax_auth: (ERROR)Unknown error, exit");
        wwa_auth_json_failure("Something went wrong.", $client_id, array(), 500);
    }catch(\Error $error){
        wwa_add_log($res_id, "ajax_auth: (ERROR)".$error->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($error));
        wwa_add_log($res_id, "ajax_auth: (ERROR)Unknown error, exit");
        wwa_auth_json_failure("Something went wrong.", $client_id, array(), 500);
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
            wwa_auth_json_failure("Bad Request.");
        }else{
            // Sanitize the input
            $post_client_id = sanitize_text_field(wp_unslash($_POST["clientid"]));
            if(strlen($post_client_id) < 34 || strlen($post_client_id) > 35){
                wwa_add_log($res_id, "ajax_auth_response: (ERROR)Wrong client ID, exit");
                wwa_auth_json_failure("Bad Request.");
            }
            $client_id = $post_client_id;
        }

        // Check POST
        if(!isset($_POST["type"]) || !isset($_POST["data"]) || !isset($_POST["remember"])){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Missing parameters, exit");
            wwa_auth_json_failure("Bad Request.", $client_id);
        }else{
            // Sanitize the input
            $wwa_post = array();
            $wwa_post["type"] = sanitize_text_field(wp_unslash($_POST["type"]));
            $wwa_post["remember"] = sanitize_text_field(wp_unslash($_POST["remember"]));
            $wwa_post["redirect_to"] = isset($_POST["redirect_to"]) ? wp_unslash($_POST["redirect_to"]) : '';
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
            wwa_auth_json_failure("Bad Request.", $client_id);
        }

        // Check remember me
        if($wwa_post["remember"] !== "true" && $wwa_post["remember"] !== "false"){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Wrong parameters, exit");
            wwa_auth_json_failure("Bad Request.", $client_id);
        }elseif(wwa_get_option("remember_me") !== "true" && $wwa_post["remember"] === "true"){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Wrong parameters, exit");
            wwa_auth_json_failure("Bad Request.", $client_id);
        }

        // May not get the challenge yet
        if($temp_val["pkcco_auth"] === false || $temp_val["usernameless_auth"] === false || ($wwa_post["type"] !== "test" && $wwa_post["type"] !== "auth")){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Challenge not found in transient, exit");
            wwa_auth_json_failure("Bad request.", $client_id);
        }

        $temp_val["usernameless_auth"] = unserialize($temp_val["usernameless_auth"], ['allowed_classes' => false]);

        if($temp_val["usernameless_auth"] === false && $temp_val["user_name_auth"] === false){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Username not found in transient, exit");
            wwa_auth_json_failure("Bad request.", $client_id);
        }
        if($wwa_post["type"] === "test" && !current_user_can("read")){
            // Test but not logged in
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Permission denied, exit");
            wwa_auth_json_failure("Bad request.", $client_id, array(), 403);
        }
        if(!($wwa_post["type"] === "test" && current_user_can("read")) && ($temp_val["usernameless_auth"] === false && $temp_val["user_auth"] === false)){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Permission denied, exit");
            wwa_auth_json_failure("Bad request.", $client_id, array(), 403);
        }

        $decoded_data = base64_decode(sanitize_text_field(wp_unslash($_POST["data"])), true);
        if(!is_string($decoded_data) || $decoded_data === ''){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Client data not correct, exit");
            wwa_auth_json_failure("Bad request.", $client_id);
        }

        $rp_id = wwa_get_rp_id();
        if($rp_id === ''){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Plugin not configured, exit");
            wwa_auth_json_failure("Not configured.", $client_id, array(), 503);
        }
        $components = wwa_get_server_components($rp_id);

        $publicKeyCredentialRequestOptions = unserialize(base64_decode($temp_val["pkcco_auth"]), ['allowed_classes' => [
            Webauthn\PublicKeyCredentialRequestOptions::class,
            Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs::class,
            Webauthn\AuthenticationExtensions\AuthenticationExtensions::class,
            Webauthn\PublicKeyCredentialDescriptor::class,
        ]]);
        if(!$publicKeyCredentialRequestOptions instanceof PublicKeyCredentialRequestOptions){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Challenge not found in transient, exit");
            wwa_auth_json_failure("Bad request.", $client_id);
        }

        $publicKeyCredential = $components['serializer']->deserialize(
            wwa_normalize_credential_response($decoded_data),
            PublicKeyCredential::class,
            'json'
        );
        wwa_assert_authentication_response_public_checks($publicKeyCredential, $publicKeyCredentialRequestOptions);

        $usernameless_flag = $temp_val["usernameless_auth"];

        $credentialRecordRepository = new CredentialRecordRepository();

        // If user entity is not saved, read from WordPress
        $user_key = "";
        if($wwa_post["type"] === "test" && current_user_can('read') && !$usernameless_flag){
            $user_info = wp_get_current_user();

            if(isset($_POST["user_id"])){
                $user_id = intval(sanitize_text_field(wp_unslash($_POST["user_id"])));
                if($user_id <= 0){
                    wwa_add_log($res_id, "ajax_auth_response: (ERROR)Wrong parameters, exit");
                    wwa_auth_json_failure("Bad Request.", $client_id);
                }

                if($user_info->ID !== $user_id){
                    if(!current_user_can("edit_user", $user_id)){
                        wwa_add_log($res_id, "ajax_auth_response: (ERROR)No permission, exit");
                        wwa_auth_json_failure("Something went wrong.", $client_id, array(), 403);
                    }
                    $user_info = get_user_by('id', $user_id);

                    if($user_info === false){
                        wwa_add_log($res_id, "ajax_auth_response: (ERROR)Wrong user ID, exit");
                        wwa_auth_json_failure("Something went wrong.", $client_id);
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
                    wwa_auth_json_failure("User not inited.", $client_id);
                }
            }
            $userEntity = wwa_get_user_entity($user_info, $user_key);

            wwa_add_log($res_id, "ajax_auth_response: type => \"test\", user => \"".$user_info->user_login."\"");
        }else{
            if($usernameless_flag){
                $assertion_user_handle = $publicKeyCredential->response->userHandle;
                if($assertion_user_handle === null || $assertion_user_handle === ''){
                    wwa_add_log($res_id, "ajax_auth_response: (ERROR)Client data not correct, exit");
                    wwa_auth_json_failure("Bad request.", $client_id);
                }

                wwa_add_log($res_id, "ajax_auth_response: type => \"".$wwa_post["type"]."\"");
                wwa_add_log($res_id, "ajax_auth_response: Usernameless authentication, try to find user by credential_id => \"".wwa_base64url_encode($publicKeyCredential->rawId)."\"");

                $credential_meta = $credentialRecordRepository->findOneMetaByCredentialId($publicKeyCredential->rawId);

                if($credential_meta !== null){
                    $allow_authenticator_type = wwa_get_option("allow_authenticator_type");
                    if($allow_authenticator_type !== false && $allow_authenticator_type !== 'none'){
                        if($credential_meta["authenticator_type"] !== $allow_authenticator_type){
                            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Credential type error, exit");
                            wwa_auth_json_failure("Bad request.", $client_id);
                        }
                    }
                    if($credential_meta["usernameless"] === true){
                        global $wpdb;
                        $cred_row = $wpdb->get_row($wpdb->prepare(
                            "SELECT user_id, user_handle FROM {$wpdb->wwa_credentials} WHERE credential_hash = %s ORDER BY id ASC LIMIT 1",
                            wwa_credential_hash($publicKeyCredential->rawId)
                        ));

                        $resolved_user_handle = null;
                        $resolved_user_info = null;

                        if($cred_row !== null){
                            $resolved_user_handle = $cred_row->user_handle;
                            $resolved_user_info = get_user_by('id', $cred_row->user_id);
                        }elseif(!is_multisite() && !get_option('wwa_credentials_migrated')){
                            wwa_add_log($res_id, "ajax_auth_response: Credential not in global table, trying legacy single-site fallback");
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
                            wwa_auth_json_failure("Bad request.", $client_id);
                        }

                        if($resolved_user_handle !== $assertion_user_handle){
                            wwa_add_log($res_id, "ajax_auth_response: (ERROR)userHandle not matched, exit");
                            wwa_auth_json_failure("Bad request.", $client_id);
                        }

                        $user_info = $resolved_user_info;
                        $user_login_name = $user_info->user_login;
                        wwa_add_log($res_id, "ajax_auth_response: Found user => \"".$user_login_name."\"");

                        if($wwa_post["type"] === "test" && current_user_can('read')){
                            $user_wp = wp_get_current_user();
                            if($user_login_name !== $user_wp->user_login){
                                wwa_add_log($res_id, "ajax_auth_response: (ERROR)User not match, exit");
                                wwa_auth_json_failure("Bad request.", $client_id);
                            }
                        }

                        $userEntity = wwa_get_user_entity($user_info, $resolved_user_handle);
                    }else{
                        wwa_add_log($res_id, "ajax_auth_response: (ERROR)Credential found, but usernameless => \"false\", exit");
                        wwa_auth_json_failure("Bad request.", $client_id);
                    }
                }else{
                    wwa_add_log($res_id, "ajax_auth_response: (ERROR)Credential not found, exit");
                    wwa_auth_json_failure("Bad request.", $client_id, array(
                        'signal' => array(
                            'type' => 'unknownCredential',
                            'payload' => wwa_get_unknown_credential_signal_payload($publicKeyCredential->rawId),
                        ),
                    ));
                }
            }else{
                wwa_add_log($res_id, "ajax_auth_response: type => \"auth\", user => \"".$temp_val["user_name_auth"]."\"");
                $userEntity = unserialize($temp_val["user_auth"], ['allowed_classes' => [
                    Webauthn\PublicKeyCredentialUserEntity::class,
                ]]);
            }
        }

        wwa_add_log($res_id, "ajax_auth_response: data => ".sanitize_text_field($decoded_data));

        if($temp_val["user_exist"]){
            // Verify
            try {
                $credentialSource = $credentialRecordRepository->findOneByCredentialId($publicKeyCredential->rawId);
                if($credentialSource === null){
                    wwa_add_log($res_id, "ajax_auth_response: (ERROR)Credential source not found, exit");
                    wwa_auth_json_failure("Something went wrong.", $client_id, array(
                        'signal' => array(
                            'type' => 'unknownCredential',
                            'payload' => wwa_get_unknown_credential_signal_payload($publicKeyCredential->rawId),
                        ),
                    ));
                }

                // check() returns the updated CredentialRecord with
                // refreshed counter / backup flags
                $updatedCredentialSource = $components['assertionValidator']->check(
                    $credentialSource,
                    $publicKeyCredential->response,
                    $publicKeyCredentialRequestOptions,
                    wwa_get_current_site_host(),
                    $userEntity->id
                );

                $credentialRecordRepository->saveCredentialRecord($updatedCredentialSource);

                wwa_add_log($res_id, "ajax_auth_response: Challenge verified");

                // Success
                $publicKeyCredentialId = $publicKeyCredential->rawId;
                $credentialRecordRepository->updateCredentialLastUsed($publicKeyCredentialId);
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
                            wwa_auth_json_failure("Something went wrong.", $client_id);
                        }

                        $user_id = $user->ID;

                        wwa_add_log($res_id, "ajax_auth_response: Log in user => \"".$user_login."\"");

                        $remember_flag = false;

                        if ($wwa_post["remember"] === "true" && (wwa_get_option("remember_me") === false ? "false" : wwa_get_option("remember_me")) !== "false") {
                            $remember_flag = true;
                            wwa_add_log($res_id, "ajax_auth_response: Remember login for 14 days");
                        }

                        wp_set_current_user($user_id, $user_login);
                        if(wwa_check_ssl()){
                            wp_set_auth_cookie($user_id, $remember_flag, true);
                        }else{
                            wp_set_auth_cookie($user_id, $remember_flag);
                        }
                        do_action("wp_login", $user_login, $user);
                    }
                }
                $success_data = array();
                if($wwa_post["type"] === "auth"){
                    $safe_redirect = wwa_normalize_login_redirect($wwa_post["redirect_to"], admin_url());
                    $success_data['redirect'] = $safe_redirect;
                    $success_data['redirect_to'] = $safe_redirect;
                }
                wwa_auth_json_success($client_id, $success_data);
            }catch(\Throwable $exception){
                // Failed to verify
                wwa_add_log($res_id, "ajax_auth_response: (ERROR)".$exception->getMessage());
                wwa_add_log($res_id, wwa_generate_call_trace($exception));
                wwa_add_log($res_id, "ajax_auth_response: (ERROR)Challenge not verified, exit");
                wwa_auth_json_failure("Something went wrong.", $client_id, array(), 500);
            }
        }else{
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)User not exists or has no authenticator, exit without verification");
            wwa_auth_json_failure("Something went wrong.", $client_id, array(), 403);
        }

        // Destroy session
        wwa_destroy_temp_val($client_id);
        exit;
    }catch(\Exception $exception){
        wwa_add_log($res_id, "ajax_auth_response: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($exception));
        wwa_add_log($res_id, "ajax_auth_response: (ERROR)Unknown error, exit");
        wwa_auth_json_failure("Something went wrong.", $client_id, array(), 500);
    }catch(\Error $error){
        wwa_add_log($res_id, "ajax_auth_response: (ERROR)".$error->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace($error));
        wwa_add_log($res_id, "ajax_auth_response: (ERROR)Unknown error, exit");
        wwa_auth_json_failure("Something went wrong.", $client_id, array(), 500);
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

    $credentialRecordRepository = new CredentialRecordRepository();
    echo wp_json_encode($credentialRecordRepository->getShowListByUserId($user_info->ID));
    exit;
}
add_action("wp_ajax_wwa_authenticator_list" , "wwa_ajax_authenticator_list");

function wwa_ajax_current_user_details_signal(){
    check_ajax_referer('wwa_ajax');

    if(!current_user_can("read")){
        wwa_wp_die("Bad Request.");
    }

    $payload = wwa_get_current_user_details_signal_payload(wp_get_current_user());
    wp_send_json(array(
        'success' => true,
        'signal' => array(
            'type' => 'currentUserDetails',
            'payload' => $payload,
        ),
        'payload' => $payload,
    ));
}
add_action("wp_ajax_wwa_current_user_details_signal", "wwa_ajax_current_user_details_signal");

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

        $credentialRecordRepository = new CredentialRecordRepository();

        if($_GET["target"] === "rename"){
            $result = $credentialRecordRepository->renameCredential(
                sanitize_text_field(wp_unslash($_GET["id"])),
                $user_info->ID,
                sanitize_text_field(wp_unslash($_GET["name"])),
                $res_id
            );
            echo $result ? "true" : "Not Found.";
        }elseif($_GET["target"] === "remove"){
            $result = $credentialRecordRepository->removeCredential(
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

    echo wp_json_encode(wwa_get_log_entries(true));

    exit;
}
add_action("wp_ajax_wwa_get_log" , "wwa_ajax_get_log");

// Clear log
function wwa_ajax_clear_log(){
    check_ajax_referer('wwa_admin_ajax');
    if(!wwa_validate_privileges()){
        wwa_wp_die("Bad Request.");
    }

    update_option("wwa_log", array());

    echo "true";
    exit;
}
add_action("wp_ajax_wwa_clear_log" , "wwa_ajax_clear_log");
