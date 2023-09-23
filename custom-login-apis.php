<?php
/*
Plugin Name: Custom Login & SSO
Description: A WordPress plugin for API login and Single Sign-On.
Version: 1.0
Author: Shantanu Goswami
*/
if ( ! defined( 'ABSPATH' ) ) exit;
include_once(plugin_dir_path(__FILE__) . 'google-oauth.php');

add_action( 'init', 'setup_init' );

function setup_init() {

    add_action('rest_api_init', function() {
      register_rest_route('custom-login/v1', 'login', array(
        'methods' => WP_REST_SERVER::CREATABLE,
        'callback' => 'custom_login_callback',
        'args' => array(),
        'permission_callback' => function () {
          return true;
        }
      ));
    });

  function custom_login_callback(WP_REST_Request $request){

    // Retrieve and sanitize username and password from the request
      $username = sanitize_text_field($request->get_param('username'));
      $password = sanitize_text_field($request->get_param('password'));

      // Check if the user exists
      $user = get_user_by('login', $username);

      if (!$user) {
        // User does not exist, create a new user
        $user_id = wp_create_user($username, $password);

        if (is_wp_error($user_id)) {
            // User creation failed, return an error response
            $response = array('message' => 'User creation failed');
            return rest_ensure_response($response)->set_status(400);
        }

        // Attempt to log in the newly created user
        $user_auth = wp_signon(array(
            'user_login'    => $username,
            'user_password' => $password,
            'remember'      => true,
        ));

        if (is_wp_error($user_auth)) {
            // Login failed, return an error response
            $response = array('message' => 'Login failed');
            wp_send_json($response, 401);
        }

        // User created and logged in successfully, return a success response
        $response = array('message' => 'User created and logged in');
        wp_send_json($response, 200);

      }
        // User exists, attempt to log in
        $user_auth = wp_signon(array(
            'user_login'    => $username,
            'user_password' => $password,
            'remember'      => true,
        ));

      if (is_wp_error($user_auth)) {
          // Login failed, return an error response
          $response = array('message' => 'Invalid credentials');
          wp_send_json($response, 400);
      }

      // Login successful, return a success response
        $response = array('message' => 'Login successful');
        wp_send_json($response, 200);

  }

}
