<?php
require_once('vendor/autoload.php');
use Webauthn\Server;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\AuthenticatorSelectionCriteria;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;

/**
 * Store all publickeys and pubilckey metas
 */
class PublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepositoryInterface {

    // Get one credential by credential ID
    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource {
        $data = $this->read();
        if(isset($data[base64_encode($publicKeyCredentialId)])){
            return PublicKeyCredentialSource::createFromArray($data[base64_encode($publicKeyCredentialId)]);
        }
        return null;
    }

    // Get all credentials of one user
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array {
        $sources = [];
        foreach($this->read() as $data){
            $source = PublicKeyCredentialSource::createFromArray($data);
            if($source->getUserHandle() === $publicKeyCredentialUserEntity->getId()){
                $sources[] = $source;
            }
        }
        return $sources;
    }

    // Save credential into database
    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void {
        $data = $this->read();
        $data_key = base64_encode($publicKeyCredentialSource->getPublicKeyCredentialId());
        $data[$data_key] = $publicKeyCredentialSource;
        $this->write($data, $data_key);
    }

    // List all authenticators
    public function getShowList(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array {
        $data = json_decode(wwa_get_option("user_credentials_meta"), true);
        $arr = array();
        $user_id = $publicKeyCredentialUserEntity->getId();
        foreach($data as $key => $value){
            if($user_id === $value["user"]){
                array_push($arr, array(
                    "key" => rtrim(strtr(base64_encode($key), '+/', '-_'), '='),
                    "name" => base64_decode($value["human_name"]),
                    "type" => $value["authenticator_type"],
                    "added" => $value["added"]
                ));
            }
        }
        return array_map(function($item){return array("key" => $item["key"], "name" => $item["name"], "type" => $item["type"], "added" => $item["added"]);}, $arr);
    }

    // Modify an authenticator
    public function modifyAuthenticator(string $id, string $name, PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity, string $action, string $res_id): string {
        $keys = $this->findAllForUserEntity($publicKeyCredentialUserEntity);
        $user_id = $publicKeyCredentialUserEntity->getId();

        // Check if the user has the authenticator
        foreach($keys as $item){
            if($item->getUserHandle() === $user_id){
                if(base64_encode($item->getPublicKeyCredentialId()) === base64_decode(str_pad(strtr($id, '-_', '+/'), strlen($id) % 4, '=', STR_PAD_RIGHT))){
                    if($action === "rename"){
                        $this->renameCredential(base64_encode($item->getPublicKeyCredentialId()), $name, $res_id);
                    }else if($action === "remove"){
                        $this->removeCredential(base64_encode($item->getPublicKeyCredentialId()), $res_id);
                    }
                    wwa_add_log($res_id, "ajax_modify_authenticator: Done");
                    return "true";
                }
            }
        }
        wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Authenticator not found, exit");
        return "Not Found.";
    }

    // Rename a credential from database by credential ID
    private function renameCredential(string $id, string $name, string $res_id): void {
        $meta = json_decode(wwa_get_option("user_credentials_meta"), true);
        wwa_add_log($res_id, "ajax_modify_authenticator: Rename \"".base64_decode($meta[$id]["human_name"])."\" -> \"".$name."\"");
        $meta[$id]["human_name"] = base64_encode($name);
        wwa_update_option("user_credentials_meta", json_encode($meta));
    }

    // Remove a credential from database by credential ID
    private function removeCredential(string $id, string $res_id): void {
        $data = $this->read();
        unset($data[$id]);
        $this->write($data, '');
        $meta = json_decode(wwa_get_option("user_credentials_meta"), true);
        wwa_add_log($res_id, "ajax_modify_authenticator: Remove \"".base64_decode($meta[$id]["human_name"])."\"");
        unset($meta[$id]);
        wwa_update_option("user_credentials_meta", json_encode($meta));
    }

    // Read credential database
    private function read(): array {
        if(wwa_get_option("user_credentials") !== NULL){
            try{
                return json_decode(wwa_get_option("user_credentials"), true);
            }catch(\Throwable $exception) {
                return [];
            }
        }
        return [];
    }

    // Save credentials data
    private function write(array $data, string $key): void {
        if(isset($_POST["type"]) && ($_POST["type"] === "platform" || $_POST["type"] == "cross-platform" || $_POST["type"] === "none") && $key !== ''){
            // Save credentials's meta separately
            $source = $data[$key]->getUserHandle();
            $meta = json_decode(wwa_get_option("user_credentials_meta"), true);
            $meta[$key] = array("human_name" => base64_encode(sanitize_text_field($_POST["name"])), "added" => date('Y-m-d H:i:s', current_time('timestamp')), "authenticator_type" => $_POST["type"], "user" => $source);
            wwa_update_option("user_credentials_meta", json_encode($meta));
        }
        wwa_update_option("user_credentials", json_encode($data));
    }
}

// Bind an authenticator
function wwa_ajax_create(){
    try{
        $res_id = wwa_generate_random_string(5);

        if(!session_id()){
            wwa_add_log($res_id, "ajax_create: Start session");
            session_start();
        }

        wwa_add_log($res_id, "ajax_create: Start");

        if(!current_user_can("read")){
            wwa_add_log($res_id, "ajax_create: (ERROR)Permission denied, exit");
            wp_die("Something went wrong.");
        }

        if(wwa_get_option('website_name') === "" || wwa_get_option('website_domain') ===""){
            wwa_add_log($res_id, "ajax_create: (ERROR)Plugin not configured, exit");
            wp_die("Not configured.");
        }

        // Check queries
        if(!isset($_GET["name"]) || !isset($_GET["type"])){
            wwa_add_log($res_id, "ajax_create: (ERROR)Missing parameters, exit");
            wp_die("Bad Request.");
        }else{
            // Sanitize the input
            $wwa_get = array();
            $wwa_get["name"] = sanitize_text_field($_GET["name"]);
            $wwa_get["type"] = sanitize_text_field($_GET["type"]);
            wwa_add_log($res_id, "ajax_create: name => \"".$wwa_get["name"]."\", type => \"".$wwa_get["type"]."\"");
        }

        if($wwa_get["name"] === ""){
            wwa_add_log($res_id, "ajax_create: (ERROR)Empty name, exit");
            wp_die("Bad Request.");
        }

        $rpEntity = new PublicKeyCredentialRpEntity(
            wwa_get_option('website_name'),
            wwa_get_option('website_domain')
        );
        $publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();

        $server = new Server(
            $rpEntity,
            $publicKeyCredentialSourceRepository,
            null
        );

        $user_info = wp_get_current_user();

        wwa_add_log($res_id, "ajax_create: user => \"".$user_info->user_login."\"");

        // Get user ID or create one
        $user_key = "";
        if(!isset(wwa_get_option("user_id")[$user_info->user_login])){
            wwa_add_log($res_id, "ajax_create: User not initialized, initialize");
            $user_array = wwa_get_option("user_id");
            $user_key = hash("sha256", $user_info->user_login."-".$user_info->display_name."-".wwa_generate_random_string(10));
            $user_array[$user_info->user_login] = $user_key;
            wwa_update_option("user_id", $user_array);
        }else{
            $user_key = wwa_get_option("user_id")[$user_info->user_login];
        }

        $user = array(
            "login" => $user_info->user_login,
            "id" => $user_key,
            "display" => $user_info->display_name
        );

        $userEntity = new PublicKeyCredentialUserEntity(
            $user["login"],
            $user["id"],
            $user["display"]
        );

        $credentialSourceRepository = new PublicKeyCredentialSourceRepository();

        $credentialSources = $credentialSourceRepository->findAllForUserEntity($userEntity);

        // Convert the Credential Sources into Public Key Credential Descriptors for excluding
        $excludeCredentials = array_map(function (PublicKeyCredentialSource $credential) {
            return $credential->getPublicKeyCredentialDescriptor();
        }, $credentialSources);

        wwa_add_log($res_id, "ajax_create: excludeCredentials => ".json_encode($excludeCredentials));

        // Set authenticator type
        if($wwa_get["type"] === "platform"){
            $authenticator_type = AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM;
        }else if($wwa_get["type"] === "cross-platform"){
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

        // Create authenticator selection
        $authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria(
            $authenticator_type,
            false,
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
        $_SESSION['wwa_server'] = serialize($server);
        $_SESSION['wwa_pkcco'] = base64_encode(serialize($publicKeyCredentialCreationOptions));

        header('Content-Type: application/json');
        echo json_encode($publicKeyCredentialCreationOptions);
        wwa_add_log($res_id, "ajax_create: Challenge sent");
        exit;
    }catch(\Exception $exception){
        wwa_add_log($res_id, "ajax_create: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace());
        wwa_add_log($res_id, "ajax_create: (ERROR)Unknown error, exit");
        wp_die("Something went wrong.");
    }catch(\Error $error){
        wwa_add_log($res_id, "ajax_create: (ERROR)".$error->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace());
        wwa_add_log($res_id, "ajax_create: (ERROR)Unknown error, exit");
        wp_die("Something went wrong.");
    }
}
add_action('wp_ajax_wwa_create' , 'wwa_ajax_create');

// Verify the attestation
function wwa_ajax_create_response(){
    try{
        $res_id = wwa_generate_random_string(5);

        if(!session_id()){
            wwa_add_log($res_id, "ajax_create_response: Start session");
            session_start();
        }

        wwa_add_log($res_id, "ajax_create_response: Client response received");

        if(!current_user_can("read")){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Permission denied, exit");
            wp_die("Something went wrong.");
        }

        // Check POST
        if(!isset($_POST["data"]) || !isset($_POST["name"]) || !isset($_POST["type"])){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Missing parameters, exit");
            wp_die("Bad Request.");
        }else{
            // Sanitize the input
            $wwa_post = array();
            $wwa_post["name"] = sanitize_text_field($_POST["name"]);
            $wwa_post["type"] = sanitize_text_field($_POST["type"]);
            wwa_add_log($res_id, "ajax_create_response: name => \"".$wwa_post["name"]."\", type => \"".$wwa_post["type"]."\"");
            wwa_add_log($res_id, "ajax_create_response: data => ".base64_decode($_POST["data"]));
        }

        // May not get the challenge yet
        if(!isset($_SESSION['wwa_server']) || !isset($_SESSION['wwa_pkcco'])){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Challenge not found in session, exit");
            wp_die("Bad request.");
        }

        if($wwa_post["type"] !== "platform" && $wwa_post["type"] !== "cross-platform" && $wwa_post["type"] !== "none"){
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Wrong type, exit");
            wp_die("Bad request.");
        }

        $psr17Factory = new Psr17Factory();
        $creator = new ServerRequestCreator(
            $psr17Factory,
            $psr17Factory,
            $psr17Factory,
            $psr17Factory
        );

        $serverRequest = $creator->fromGlobals();

        $server = unserialize($_SESSION['wwa_server']);

        // Allow to bypass scheme verification when under localhost
        $current_domain = wwa_get_option('website_domain');
        if($current_domain === "localhost" || $current_domain === "127.0.0.1"){
            $server->setSecuredRelyingPartyId([$current_domain]);
            wwa_add_log($res_id, "ajax_create_response: Localhost, bypass HTTPS check");
        }

        // Verify
        try {
            $publicKeyCredentialSource = $server->loadAndCheckAttestationResponse(
                base64_decode($_POST["data"]),
                unserialize(base64_decode($_SESSION['wwa_pkcco'])),
                $serverRequest
            );

            wwa_add_log($res_id, "ajax_create_response: Challenge verified");

            $publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();
            $publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);

            wwa_add_log($res_id, "ajax_create_response: Authenticator added");
            // Success
            echo 'true';
        }catch(\Throwable $exception){
            // Failed to verify
            wwa_add_log($res_id, "ajax_create_response: (ERROR)".$exception->getMessage());
            wwa_add_log($res_id, wwa_generate_call_trace());
            wwa_add_log($res_id, "ajax_create_response: (ERROR)Challenge not verified, exit");
            wp_die("Something went wrong.");
        }
        exit;
    }catch(\Exception $exception){
        wwa_add_log($res_id, "ajax_create_response: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace());
        wwa_add_log($res_id, "ajax_create_response: (ERROR)Unknown error, exit");
        wp_die("Something went wrong.");
    }catch(\Error $error){
        wwa_add_log($res_id, "ajax_create_response: (ERROR)".$error->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace());
        wwa_add_log($res_id, "ajax_create_response: (ERROR)Unknown error, exit");
        wp_die("Something went wrong.");
    }
}
add_action('wp_ajax_wwa_create_response' , 'wwa_ajax_create_response');

// Auth challenge
function wwa_ajax_auth_start(){
    try{
        $res_id = wwa_generate_random_string(5);

        if(!session_id()){
            wwa_add_log($res_id, "auth: Start session");
            session_start();
        }

        wwa_add_log($res_id, "ajax_auth: Start");

        // Check queries
        if(!isset($_GET["type"])){
            wwa_add_log($res_id, "ajax_auth: (ERROR)Missing parameters, exit");
            wp_die("Bad Request.");
        }else{
            // Sanitize the input
            $wwa_get = array();
            $wwa_get["type"] = sanitize_text_field($_GET["type"]);
            if(isset($_GET["user"])){
                $wwa_get["user"] = sanitize_text_field($_GET["user"]);
            }
        }

        $user_key = "";
        if($wwa_get["type"] === "test" && current_user_can('read')){
            // Logged in and testing, if the user haven't bound any authenticator yet, exit
            $user_info = wp_get_current_user();

            wwa_add_log($res_id, "ajax_auth: type => \"test\", user => \"".$user_info->user_login."\"");

            if(!isset(wwa_get_option("user_id")[$user_info->user_login])){
                wwa_add_log($res_id, "ajax_auth: (ERROR)User not initialized, exit");
                wp_die("User not inited.");
            }else{
                $user_key = wwa_get_option("user_id")[$user_info->user_login];
            }
        }else{
            // Not testing, create a fake user ID if the user does not exist or haven't bound any authenticator yet
            if(isset($wwa_get["user"])){
                if(get_user_by('login', $wwa_get["user"])){
                    $user_info = get_user_by('login', $wwa_get["user"]);wwa_add_log($res_id, "ajax_auth: type => \"auth\", user => \"".$user_info->user_login."\"");
                    if(!isset(wwa_get_option("user_id")[$user_info->user_login])){
                        wwa_add_log($res_id, "ajax_auth: User not initialized, initialize");
                        $user_key = hash("sha256", $wwa_get["user"]."-".$wwa_get["user"]."-".wwa_generate_random_string(10));
                    }else{
                        $user_key = wwa_get_option("user_id")[$user_info->user_login];
                    }
                }else{
                    $user_info = new stdClass();
                    $user_info->user_login = $wwa_get["user"];
                    $user_info->display_name = $wwa_get["user"];
                    $user_key = hash("sha256", $wwa_get["user"]."-".$wwa_get["user"]."-".wwa_generate_random_string(10));
                    wwa_add_log($res_id, "ajax_auth: type => \"auth\"");
                    wwa_add_log($res_id, "ajax_auth: User not exists, create a fake id");
                }
            }else{
                wwa_add_log($res_id, "ajax_auth: (ERROR)Missing parameters, exit");
                wp_die("Bad Request.");
            }
        }

        $userEntity = new PublicKeyCredentialUserEntity(
            $user_info->user_login,
            $user_key,
            $user_info->display_name
        );

        $credentialSourceRepository = new PublicKeyCredentialSourceRepository();
        $rpEntity = new PublicKeyCredentialRpEntity(
            wwa_get_option('website_name'),
            wwa_get_option('website_domain')
        );

        $server = new Server(
            $rpEntity,
            $credentialSourceRepository,
            null
        );

        // Get the list of authenticators associated to the user
        $credentialSources = $credentialSourceRepository->findAllForUserEntity($userEntity);

        // Logged in and testing, if the user haven't bind a authenticator yet, exit
        if(count($credentialSources) === 0 && $wwa_get["type"] === "test" && current_user_can('read')){
            wwa_add_log($res_id, "ajax_auth: (ERROR)No authenticator, exit");
            wp_die("User not inited.");
        }

        // Convert the Credential Sources into Public Key Credential Descriptors for excluding
        $allowedCredentials = array_map(function (PublicKeyCredentialSource $credential) {
            return $credential->getPublicKeyCredentialDescriptor();
        }, $credentialSources);

        wwa_add_log($res_id, "ajax_auth: allowedCredentials => ".json_encode($allowedCredentials));

        // Set user verification
        if(wwa_get_option("user_verification") === "true"){
            wwa_add_log($res_id, "ajax_auth: user_verification => \"true\"");
            $user_verification = AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED;
        }else{
            wwa_add_log($res_id, "ajax_auth: user_verification => \"false\"");
            $user_verification = AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
        }

        // Create a auth challenge
        $publicKeyCredentialRequestOptions = $server->generatePublicKeyCredentialRequestOptions(
            $user_verification,
            $allowedCredentials
        );

        // Save for future use
        $_SESSION['wwa_server_auth'] = serialize($server);
        $_SESSION['wwa_pkcco_auth'] = base64_encode(serialize($publicKeyCredentialRequestOptions));
        $_SESSION['wwa_user_name_auth'] = $user_info->user_login;

        // Save the user entity if is not logged in
        if(!($wwa_get["type"] === "test" && current_user_can('read'))){
            $_SESSION['wwa_user_auth'] = serialize($userEntity);
        }

        header('Content-Type: application/json');
        echo json_encode($publicKeyCredentialRequestOptions);
        wwa_add_log($res_id, "ajax_auth: Challenge sent");
        exit;
    }catch(\Exception $exception){
        wwa_add_log($res_id, "ajax_auth: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace());
        wwa_add_log($res_id, "ajax_auth: (ERROR)Unknown error, exit");
        wp_die("Something went wrong.");
    }catch(\Error $error){
        wwa_add_log($res_id, "ajax_auth: (ERROR)".$error->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace());
        wwa_add_log($res_id, "ajax_auth: (ERROR)Unknown error, exit");
        wp_die("Something went wrong.");
    }
}
add_action('wp_ajax_wwa_auth_start' , 'wwa_ajax_auth_start');
add_action('wp_ajax_nopriv_wwa_auth_start' , 'wwa_ajax_auth_start');

function wwa_ajax_auth(){
    try{
        $res_id = wwa_generate_random_string(5);

        if(!session_id()){
            wwa_add_log($res_id, "auth_response: Start session");
            session_start();
        }

        wwa_add_log($res_id, "ajax_auth_response: Client response received");

        // Check POST
        if(!isset($_POST["type"]) || !isset($_POST["data"])){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Missing parameters, exit");
            wp_die("Bad Request.");
        }else{
            // Sanitize the input
            $wwa_post = array();
            $wwa_post["type"] = sanitize_text_field($_POST["type"]);
        }

        // May not get the challenge yet
        if(!isset($_SESSION['wwa_server_auth']) || !isset($_SESSION['wwa_pkcco_auth']) || !isset($_SESSION['wwa_user_name_auth']) || ($wwa_post["type"] !== "test" && $wwa_post["type"] !== "auth")){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Challenge not found in session, exit");
            wp_die("Bad request.");
        }
        if(!($wwa_post["type"] === "test" && current_user_can('read')) && !isset($_SESSION['wwa_user_auth'])){
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Permission denied, exit");
            wp_die("Bad request.");
        }

        $psr17Factory = new Psr17Factory();
        $creator = new ServerRequestCreator(
            $psr17Factory,
            $psr17Factory,
            $psr17Factory,
            $psr17Factory
        );

        $serverRequest = $creator->fromGlobals();

        // If user entity is not saved, read from WordPress
        $user_key = "";
        if($wwa_post["type"] === "test" && current_user_can('read')){
            $user_info = wp_get_current_user();

            if(!isset(wwa_get_option("user_id")[$user_info->user_login])){
                wwa_add_log($res_id, "ajax_auth_response: (ERROR)User not initialized, exit");
                wp_die("User not inited.");
            }else{
                $user_key = wwa_get_option("user_id")[$user_info->user_login];
            }

            $userEntity = new PublicKeyCredentialUserEntity(
                $user_info->user_login,
                $user_key,
                $user_info->display_name
            );

            wwa_add_log($res_id, "ajax_auth_response: type => \"test\", user => \"".$user_info->user_login."\"");
        }else{
            wwa_add_log($res_id, "ajax_auth_response: type => \"auth\", user => \"".$_SESSION['wwa_user_name_auth']."\"");
            $userEntity = unserialize($_SESSION['wwa_user_auth']);
        }

        wwa_add_log($res_id, "ajax_auth_response: data => ".base64_decode($_POST["data"]));

        $server = unserialize($_SESSION['wwa_server_auth']);

        // Allow to bypass scheme verification when under localhost
        $current_domain = wwa_get_option('website_domain');
        if($current_domain === "localhost" || $current_domain === "127.0.0.1"){
            $server->setSecuredRelyingPartyId([$current_domain]);
            wwa_add_log($res_id, "ajax_auth_response: Localhost, bypass HTTPS check");
        }

        // Verify
        try {
            $publicKeyCredentialSource = $server->loadAndCheckAssertionResponse(
                base64_decode($_POST["data"]),
                unserialize(base64_decode($_SESSION['wwa_pkcco_auth'])),
                $userEntity,
                $serverRequest
            );

            wwa_add_log($res_id, "ajax_auth_response: Challenge verified");

            // Success
            if(!($wwa_post["type"] === "test" && current_user_can('read'))){
                // Log user in
                if (!is_user_logged_in()) {
                    include('wwa-compatibility.php');

                    $user_login = $_SESSION['wwa_user_name_auth'];

                    $user =  get_user_by('login', $user_login);
                    $user_id = $user->ID;

                    wwa_add_log($res_id, "ajax_auth_response: Log in user => \"".$_SESSION['wwa_user_name_auth']."\"");

                    wp_set_current_user($user_id, $user_login);
                    if(isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'){
                        wp_set_auth_cookie($user_id, false, true);
                    }else{
                        wp_set_auth_cookie($user_id, false);
                    }
                    do_action('wp_login', $user_login, $user);
                }
            }
            echo "true";
        }catch(\Throwable $exception){
            // Failed to verify
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)".$exception->getMessage());
            wwa_add_log($res_id, wwa_generate_call_trace());
            wwa_add_log($res_id, "ajax_auth_response: (ERROR)Challenge not verified, exit");
            wp_die("Something went wrong.");
        }
        exit;
    }catch(\Exception $exception){
        wwa_add_log($res_id, "ajax_auth_response: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace());
        wwa_add_log($res_id, "ajax_auth_response: (ERROR)Unknown error, exit");
        wp_die("Something went wrong.");
    }catch(\Error $error){
        wwa_add_log($res_id, "ajax_auth_response: (ERROR)".$error->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace());
        wwa_add_log($res_id, "ajax_auth_response: (ERROR)Unknown error, exit");
        wp_die("Something went wrong.");
    }
}
add_action('wp_ajax_wwa_auth' , 'wwa_ajax_auth');
add_action('wp_ajax_nopriv_wwa_auth' , 'wwa_ajax_auth');

// Get authenticator list
function wwa_ajax_authenticator_list(){
    $res_id = wwa_generate_random_string(5);

    if(!current_user_can("read")){
        wwa_add_log($res_id, "ajax_ajax_authenticator_list: (ERROR)Missing parameters, exit");
        wp_die("Something went wrong.");
    }
    header('Content-Type: application/json');

    $user_info = wp_get_current_user();

    $user_key = "";
    if(!isset(wwa_get_option("user_id")[$user_info->user_login])){
        wwa_add_log($res_id, "ajax_ajax_authenticator_list: Empty authenticator list");
        // The user haven't bound any authenticator, return empty list
        echo "[]";
        exit;
    }else{
        $user_key = wwa_get_option("user_id")[$user_info->user_login];
    }

    $userEntity = new PublicKeyCredentialUserEntity(
        $user_info->user_login,
        $user_key,
        $user_info->display_name
    );

    $publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();
    echo json_encode($publicKeyCredentialSourceRepository->getShowList($userEntity));
    exit;
}
add_action('wp_ajax_wwa_authenticator_list' , 'wwa_ajax_authenticator_list');

// Modify an authenticator
function wwa_ajax_modify_authenticator(){
    try{
        $res_id = wwa_generate_random_string(5);

        wwa_add_log($res_id, "ajax_modify_authenticator: Start");

        if(!current_user_can("read")){
            wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Permission denied, exit");
            wp_die("Bad Request.");
        }

        if(!isset($_GET["id"]) || !isset($_GET["target"])){
            wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Missing parameters, exit");
            wp_die("Bad Request.");
        }

        if($_GET["target"] !== "rename" && $_GET["target"] !== "remove"){
            wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Wrong target, exit");
            wp_die("Bad Request.");
        }

        if($_GET["target"] === "rename" && !isset($_GET["name"])){
            wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Missing parameters, exit");
            wp_die("Bad Request.");
        }

        $user_info = wp_get_current_user();

        $user_key = "";
        if(!isset(wwa_get_option("user_id")[$user_info->user_login])){
            // The user haven't bound any authenticator, exit
            wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)User not initialized, exit");
            wp_die("User not inited.");
        }else{
            $user_key = wwa_get_option("user_id")[$user_info->user_login];
        }

        $userEntity = new PublicKeyCredentialUserEntity(
            $user_info->user_login,
            $user_key,
            $user_info->display_name
        );
        
        wwa_add_log($res_id, "ajax_modify_authenticator: user => \"".$user_info->user_login."\"");

        $publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();

        if($_GET["target"] === "rename"){
            echo $publicKeyCredentialSourceRepository->modifyAuthenticator($_GET["id"], sanitize_text_field($_GET["name"]), $userEntity, "rename", $res_id);
        }else if($_GET["target"] === "remove"){
            echo $publicKeyCredentialSourceRepository->modifyAuthenticator($_GET["id"], "", $userEntity, "remove", $res_id);
        }
        exit;
    }catch(\Exception $exception){
        wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)".$exception->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace());
        wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Unknown error, exit");
        wp_die("Something went wrong.");
    }catch(\Error $error){
        wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)".$error->getMessage());
        wwa_add_log($res_id, wwa_generate_call_trace());
        wwa_add_log($res_id, "ajax_modify_authenticator: (ERROR)Unknown error, exit");
        wp_die("Something went wrong.");
    }
}
add_action('wp_ajax_wwa_modify_authenticator' , 'wwa_ajax_modify_authenticator');

// Print log
function wwa_ajax_get_log(){
    if(!current_user_can("edit_plugins")){
        wp_die("Bad Request.");
    }

    header('Content-Type: application/json');

    $log = get_option("wwa_log");

    if($log === false){
        echo "[]";
    }else{
        echo json_encode($log);
    }
    
    exit;
}
add_action('wp_ajax_wwa_get_log' , 'wwa_ajax_get_log');

// Clear log
function wwa_ajax_clear_log(){
    if(!current_user_can("edit_plugins")){
        wp_die("Bad Request.");
    }

    $log = get_option("wwa_log");

    if($log !== false){
        update_option("wwa_log", array());
    }
    
    echo "true";
    exit;
}
add_action('wp_ajax_wwa_clear_log' , 'wwa_ajax_clear_log');
?>