<?php
/**
 * Handling global REST API requests.
 */

namespace GoogleOauth;
use \GoogleOauth\REST_API\Login;

class REST_APIS {

	private $routes = array();

	public function __construct() {
		include_once 'rest-api/class-login.php';
	}


	public function register_hooks() {

		add_action( 'rest_api_init', array( $this, 'prepare_route' ) );
	}

	public function prepare_route() {

		$login = new Login();
		$this->routes = array_merge( $this->routes, $login->get_routes() );

		foreach ( $this->routes as $route ) {
			\register_rest_route( 'custom-login', $route['route'], $route['config'] );
		}

	}
}
