<?php

namespace GoogleOauth\REST_API;
use \Firebase\JWT\JWT;

class Login extends REST_API {

	protected $googleClient = '553458875012-ru9e8slr1aith80c3eu526csp2dne26k.apps.googleusercontent.com';
	protected $path = 'sso';

	public function __construct() {
		$this->prepare_google();

		$this->add_route( 'google', array(
			'methods' => \WP_REST_Server::CREATABLE,
			'callback' => array( $this, 'login_google' ),
		));
	}

	protected function find_user_by( $key, $value ) {
		$user = false;

		switch ( $key ) {
			case 'google_id':
				$user_query = new \WP_User_Query(
					array(
						'meta_key'   => '_google_user_id',
						'meta_value' => $value
					)
				);

				// Get the results from the query, returning the first user
				$users = $user_query->get_results();
				if ( is_array( $users ) && $users ) {

					$user = $users[0];
					$user = new \WP_User( $user->ID );

				}
				break;
			default:
				$user = \get_user_by( $key, $value );
				break;
		}

		return $user;
	}


	protected function prepare_google() {
		if ( ! $this->googleClient && defined( 'GOOGLEOAUTH_GOOGLE_CLIENT_ID' ) ) {
			$this->googleClient = HEADLESS_GOOGLE_CLIENT_ID;
		}
	}


	/**
	 * Create the user.
	 *
	 * @param string $username
	 * @param string $email
	 *
	 * @return integer User ID.
	 */
	protected function create_user( $username, $email, $password = '' ) {
		if ( username_exists( $username ) ) {
			$username .= date( 'YmdHis');
		}

		if ( ! $password ) {
			$password = wp_generate_password();
		}

		$user_id = wp_create_user( $username, $password, $email );

		return $user_id;
	}

	/**
	 * Create the token for the User.
	 */
	protected function create_token( $user ) {
		$secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;

		/** check the secret key if not exist return a error*/
		if (!$secret_key) {
			return new \WP_Error(
				'jwt_auth_bad_config',
				__('JWT is not configurated properly', 'wp-api-jwt-auth'),
				array(
					'status' => 403,
				)
			);
		}

		/** Valid credentials, the user exists create the according Token */
		$issuedAt = time();
		$notBefore = apply_filters('jwt_auth_not_before', $issuedAt, $issuedAt);
		$expire = apply_filters('jwt_auth_expire', $issuedAt + (DAY_IN_SECONDS * 7), $issuedAt);

		$token = array(
			'iss' => get_bloginfo('url'),
			'iat' => $issuedAt,
			'nbf' => $notBefore,
			'exp' => $expire,
			'data' => array(
				'user' => array(
					'id' => $user->ID,
				),
			),
		);

		/** Let the user modify the token data before the sign. */
		$token = JWT::encode(apply_filters('jwt_auth_token_before_sign', $token, $user), $secret_key);

		$data = array(
			'token' => $token,
			'user_email' => $user->user_email,
			'user_nicename' => $user->user_nicename,
			'user_display_name' => $user->display_name,
		);

		/** Let the user modify the data before send it back */
		return apply_filters('jwt_auth_token_before_dispatch', $data, $user);
	}

	public function login_google( $request ) {
		header( 'Access-Control-Allow-Origin: *' );

		$params = $request->get_params();
		$token  = isset( $params['token'] ) ? $params['token'] : false;

		if ( ! $token ) {
			return new \WP_Error( 'no-token', __( 'No token received from Google', 'shan' ) );
		}

		if ( ! class_exists( 'Google_Client' ) ) {
			include_once plugin_dir_path( GOOGLEOAUTH_FILE ) . '/vendor/google/apiclient/src/Client.php';
		}

		$client = new \Google_Client( [ 'client_id' => $this->googleClient ] );  // Specify the CLIENT_ID of the app that accesses the backend

		try {
			$payload = $client->verifyIdToken( $token );
			if ( $payload ) {
				$google_user_id = $payload['sub'];
				$email = $payload['email'];
				$name  = $payload['name'];

				$user = $this->find_user_by( 'google_id', $google_user_id );

				if ( is_a( $user, 'WP_User' ) ) {

					update_user_meta( $user->ID, '_google_token', $token );

					return $this->create_token( $user );
				} else {
					$user = $this->find_user_by( 'email', $email );
					if ( ! $user ) {
						$username   = str_replace( ' ', '', $name );
						$user_id    = $this->create_user( $username, $email );
						$first_name = isset( $payload['given_name'] ) ? $payload['given_name'] : $name;
						$last_name  = isset( $payload['family_name'] ) ? $payload['family_name'] : '';
						if ( is_wp_error( $user_id ) ) {
							return $user_id;
						}

						$user = new \WP_User( $user_id );
						wp_update_user( array( 'ID'           => $user_id,
						                       'display_name' => $name,
						                       'first_name'   => $first_name,
						                       'last_name'    => $last_name
						) );
					}

					add_user_meta( $user->ID, '_google_user_id', $google_user_id );
					add_user_meta( $user->ID, '_google_token', $token );

					return $this->create_token( $user );
				}
			} else {
				return new \WP_Error( 'invalid-token', __( 'Token is not valid', 'shan' ) );
			}
		} catch ( \Exception $e ) {
			return new \WP_Error( $e->getCode(), $e->getMessage() );
		}

	}
}
