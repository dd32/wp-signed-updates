<?php
namespace dd32\WordPressSignedUpdates\MockAPI;
/*
 * Plugin Name: WordPress Signing, 2020, Mock API.
 * Plugin URI: https://github.com/dd32/wp-signed-updates
 * Description: This plugin does stuff, mocking API.w.org
 * Author: Dion Hulse
 * Version: 0.2
 * Author URI: https://dd32.id.au/
 */

include_once __DIR__ . '/compat.php';

class Plugin {
	protected function __construct() {
		add_filter( 'pre_http_request', [ $this, 'intercept' ], 10, 3 );
	}

	static $instance;
	public static function instance() {
		return self::$instance ?? self::$instance = new Plugin;
	}

	public function intercept( $filter_value, $args, $url ) {
		$url_parts = wp_parse_url( $url );

		if ( 'api.wordpress.org' === $url_parts['host'] ) {
			if (
				str_starts_with( $url_parts['path'], '/key-manifests/' ) &&
				str_ends_with( $url_parts['path'], '.json' )
			) {
				$key = basename( $url_parts['path'], '.json' );
				return $this->mock_http_response( $this->generate_manifest_payload( $key ) );
			}
		}

		return $filter_value;
	}

	public function generate_manifest_payload( $key ) {
		// $key is hex encoded key.
		foreach ( glob( "./keys/*.json" ) as $file ) {
			$data = json_decode( $json = file_get_contents( $file ), true );
			if ( $data && isset( $data['key'] ) && $key === $data['key'] ) {
				return $json;
			}
		}

		return false;
	}

	protected function mock_http_response( $data ) {
		return array(
			'body' => $data,
			'response' => array(
				'code' => $data ? 200 : 404,
				'message' => $data ? 'OK' : 'Not Found',
			),
			'headers' => array(),
			'cookies' => array(),
			'filename' => null,
		);
	}
}
Plugin::instance();
