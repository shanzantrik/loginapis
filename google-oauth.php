<?php
namespace GoogleOauth;

if ( ! defined( 'ABSPATH' ) ) {
    return;
}

define( 'GOOGLEOAUTH_FILE', __FILE__ );

class GoogleOauth {

public function __construct() {
        $this->includes();
        $this->run();
    }

    public function includes() {
        include_once 'vendor/autoload.php';

        include_once 'includes/abstracts/class-rest-api.php';

        include_once 'includes/class-rest-apis.php';
    }
    public function run() {
        $rest_apis = new REST_APIS();
        $rest_apis->register_hooks();

        if ( function_exists( 'register_meta' ) ) {
            register_meta( 'user', 'avatar', [ 'show_in_rest' => true ]);
            register_meta( 'user', 'avatar_id', [ 'show_in_rest' => true ]);
        }
    }

}
new GoogleOauth();
