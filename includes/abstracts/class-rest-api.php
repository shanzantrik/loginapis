<?php

namespace GoogleOauth\REST_API;

class REST_API {

	protected $version = 'v1';

	protected $path = '';

	protected $routes = array();

	public function get_routes() {
		return $this->routes;
	}

	public function add_route( $route, $config ) {
		$this->routes[] = array(
			'route' => $this->version . '/' . $this->path . '/' . $route,
			'config' => $config
		);
	}
}
