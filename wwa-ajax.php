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
        if (isset($data[base64_encode($publicKeyCredentialId)])){
            return PublicKeyCredentialSource::createFromArray($data[base64_encode($publicKeyCredentialId)]);
        }
        return null;
    }

    // Get all credentials of one user
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array {
        $sources = [];
        foreach($this->read() as $data){
            $source = PublicKeyCredentialSource::createFromArray($data);
            if ($source->getUserHandle() === $publicKeyCredentialUserEntity->getId()){
                $sources[] = $source;
            }
        }
        return $sources;
    }

    // Save credential into deatbase
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

    // Remove an authenticator
    public function removeAuthenticator(string $id, PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): string {
        $keys = $this->findAllForUserEntity($publicKeyCredentialUserEntity);
        $user_id = $publicKeyCredentialUserEntity->getId();

        // Check if the user has the authenticator
        foreach($keys as $item){
            if($item->getUserHandle() === $user_id){
                if(base64_encode($item->getPublicKeyCredentialId()) === base64_decode(str_pad(strtr($id, '-_', '+/'), strlen($id) % 4, '=', STR_PAD_RIGHT))){
                    $this->removeCredential(base64_encode($item->getPublicKeyCredentialId()));
                    return "true";
                }
            }
        }
        return "Not Found.";
    }

    // Remove a credential from database by credential ID
    private function removeCredential(string $id): void {
        $data = $this->read();
        unset($data[$id]);
        $this->write($data, '');
        $meta = json_decode(wwa_get_option("user_credentials_meta"), true);
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
            $meta[$key] = array("human_name" => base64_encode($_POST["name"]), "added" => date('Y-m-d H:i:s'), "authenticator_type" => $_POST["type"], "user" => $source);
            wwa_update_option("user_credentials_meta", json_encode($meta));
        }
        wwa_update_option("user_credentials", json_encode($data));
    }
}

// Bind an authenticator
function wwa_ajax_create(){
    if(!session_id()){
        session_start();
    }
    if(!current_user_can("read")){
        wp_die("Something went wrong.");
    }

    // Check queries
    if(!isset($_GET["name"]) || !isset($_GET["type"])){
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

    // Get user ID or create one
    $user_key = "";
    if(!isset(wwa_get_option("user_id")[$user_info->user_login])){
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

    // Set authenticator type
    if($_GET["type"] === "platform"){
        $authenticator_type = AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM;
    }else if($_GET["type"] === "cross-platform"){
        $authenticator_type = AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
    }else{
        $authenticator_type = AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE;
    }

    // Create authenticator selection
    $authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria(
        $authenticator_type,
        false,
        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED
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
    exit;
}
add_action('wp_ajax_wwa_create' , 'wwa_ajax_create');

// Verify the attestation
function wwa_ajax_create_response(){
    if(!session_id()){
        session_start();
    }
    if(!current_user_can("read")){
        wp_die("Something went wrong.");
    }

    // Check POST
    if(!isset($_POST["data"]) || !isset($_POST["name"]) || !isset($_POST["type"])){
        wp_die("Bad Request.");
    }

    // May not get the challenge yet
    if(!isset($_SESSION['wwa_server']) || !isset($_SESSION['wwa_pkcco']) || ($_POST["type"] !== "platform" && $_POST["type"] !== "cross-platform" && $_POST["type"] !== "none")){
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

    // Verify
    $server = unserialize($_SESSION['wwa_server']);
    try {
        $publicKeyCredentialSource = $server->loadAndCheckAttestationResponse(
            base64_decode($_POST["data"]),
            unserialize(base64_decode($_SESSION['wwa_pkcco'])),
            $serverRequest
        );

        $publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();
        $publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);

        // Success
        echo 'true';
    }catch(\Throwable $exception){
        // Failed to verify
        wp_die("Something went wrong.");
    }
    exit;
}
add_action('wp_ajax_wwa_create_response' , 'wwa_ajax_create_response');

// Auth challenge
function wwa_ajax_auth_start(){
    if(!session_id()){
        session_start();
    }

    // Check queries
    if(!isset($_GET["type"])){
        wp_die("Bad Request.");
    }

    $user_key = "";
    if($_GET["type"] === "test" && current_user_can('read')){
        // Logged in and testing, if the user haven't bound any authenticator yet, exit
        $user_info = wp_get_current_user();

        if(!isset(wwa_get_option("user_id")[$user_info->user_login])){
            wp_die("User not inited.");
        }else{
            $user_key = wwa_get_option("user_id")[$user_info->user_login];
        }
    }else{
        // Not testing, create a fake user ID if the user does not exist or haven't bound any authenticator yet
        if(isset($_GET["user"])){
            if(get_user_by('login', $_GET["user"])){
                $user_info = get_user_by('login', $_GET["user"]);
                if(!isset(wwa_get_option("user_id")[$user_info->user_login])){
                    $user_key = hash("sha256", $_GET["user"]."-".$_GET["user"]."-".wwa_generate_random_string(10));
                }else{
                    $user_key = wwa_get_option("user_id")[$user_info->user_login];
                }
            }else{
                $user_info = new stdClass();
                $user_info->user_login = $_GET["user"];
                $user_info->display_name = $_GET["user"];
                $user_key = hash("sha256", $_GET["user"]."-".$_GET["user"]."-".wwa_generate_random_string(10));
            }
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
    if(count($credentialSources) === 0 && $_GET["type"] === "test" && current_user_can('read')){
        wp_die("User not inited.");
    }

    // Convert the Credential Sources into Public Key Credential Descriptors for excluding
    $allowedCredentials = array_map(function (PublicKeyCredentialSource $credential) {
        return $credential->getPublicKeyCredentialDescriptor();
    }, $credentialSources);

    // Create a auth challenge
    $publicKeyCredentialRequestOptions = $server->generatePublicKeyCredentialRequestOptions(
        PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        $allowedCredentials
    );

    // Save for future use
    $_SESSION['wwa_server_auth'] = serialize($server);
    $_SESSION['wwa_pkcco_auth'] = base64_encode(serialize($publicKeyCredentialRequestOptions));

    // Save the user if is not logged in
    if(!($_GET["type"] === "test" && current_user_can('read'))){
        $_SESSION['wwa_user_auth'] = serialize($userEntity);
    }

    header('Content-Type: application/json');
    echo json_encode($publicKeyCredentialRequestOptions);
    exit;
}
add_action('wp_ajax_wwa_auth_start' , 'wwa_ajax_auth_start');
add_action('wp_ajax_nopriv_wwa_auth_start' , 'wwa_ajax_auth_start');

function wwa_ajax_auth(){
    if(!session_id()){
        session_start();
    }

    // Check POST
    if(!isset($_POST["type"]) || !isset($_POST["data"])){
        wp_die("Bad Request.");
    }

    // May not get the challenge yet
    if(!isset($_SESSION['wwa_server_auth']) || !isset($_SESSION['wwa_pkcco_auth']) || ($_POST["type"] !== "test" && $_POST["type"] !== "auth")){
        wp_die("Bad request.");
    }
    if(!($_POST["type"] === "test" && current_user_can('read')) && !isset($_SESSION['wwa_user_auth'])){
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
    if($_POST["type"] === "test" && current_user_can('read')){
        $user_info = wp_get_current_user();

        if(!isset(wwa_get_option("user_id")[$user_info->user_login])){
            wp_die("User not inited.");
        }else{
            $user_key = wwa_get_option("user_id")[$user_info->user_login];
        }

        $userEntity = new PublicKeyCredentialUserEntity(
            $user_info->user_login,
            $user_key,
            $user_info->display_name
        );
    }else{
        $userEntity = unserialize($_SESSION['wwa_user_auth']);
    }

    // Verify
    $server = unserialize($_SESSION['wwa_server_auth']);
    try {
        $publicKeyCredentialSource = $server->loadAndCheckAssertionResponse(
            base64_decode($_POST["data"]),
            unserialize(base64_decode($_SESSION['wwa_pkcco_auth'])),
            $userEntity,
            $serverRequest
        );

        // Success
        if(!($_POST["type"] === "test" && current_user_can('read'))){
            // Log user in
            if (!is_user_logged_in()) {
                $user_login = $_POST["user"];

                $user =  get_user_by('login', $user_login);
                $user_id = $user->ID;

                wp_set_current_user($user_id, $user_login);
                if(isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'){
                    wp_set_auth_cookie($user_id, false, true);
                }else{
                    wp_set_auth_cookie($user_id, false);
                }
                do_action('wp_login', $user_login);
            }
        }
        echo "true";
    }catch(\Throwable $exception){
        // Failed to verify
        wp_die("Something went wrong.");
    }
    exit;
}
add_action('wp_ajax_wwa_auth' , 'wwa_ajax_auth');
add_action('wp_ajax_nopriv_wwa_auth' , 'wwa_ajax_auth');

// Get authenticator list
function wwa_ajax_authenticator_list(){
    if(!current_user_can("read")){
        wp_die("Something went wrong.");
    }
    header('Content-Type: application/json');

    $user_info = wp_get_current_user();

    $user_key = "";
    if(!isset(wwa_get_option("user_id")[$user_info->user_login])){
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

// Remove an authenticator
function wwa_ajax_remove_authenticator(){
    if(!current_user_can("read") || !isset($_GET["id"])){
        wp_die("Bad Request.");
    }

    $user_info = wp_get_current_user();

    $user_key = "";
    if(!isset(wwa_get_option("user_id")[$user_info->user_login])){
        // The user haven't bound any authenticator, exit
        wp_die("User not inited.");
    }else{
        $user_key = wwa_get_option("user_id")[$user_info->user_login];
    }

    $userEntity = new PublicKeyCredentialUserEntity(
        $user_info->user_login,
        $user_key,
        $user_info->display_name
    );

    $publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();
    echo $publicKeyCredentialSourceRepository->removeAuthenticator($_GET["id"], $userEntity);
    exit;
}
add_action('wp_ajax_wwa_remove_authenticator' , 'wwa_ajax_remove_authenticator');
?>