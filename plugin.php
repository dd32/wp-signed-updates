<?php
namespace dd32\WordPressSignedUpdates;
/*
 * Plugin Name: WordPress Signing, 2020
 * Plugin URI: https://github.com/dd32/wp-signed-updates
 * Description: This plugin does stuff. Client-side stuff.
 * Author: Dion Hulse
 * Version: 0.2
 * Author URI: https://dd32.id.au/
 */

include_once __DIR__ . '/compat.php';

class Plugin {

	protected $trusted_root_keys = [
		// Hex encoded binary ed25519 keys
		'39f6eb7cd5c98ff9244dc8489a1f9f793510c456a9e2a8349319e18808136634' => [
			'key'        => '39f6eb7cd5c98ff9244dc8489a1f9f793510c456a9e2a8349319e18808136634',
			'desc'       => 'Root Key #1',
			'date'       => '2020-01-01T00:00:00Z',
			'validUntil' => '2035-01-01T00:00:00Z',
			'canSign'    => [ 'key' ],
			'signature'  => []
		],
		'e470c61ff127b87010dd8f4bd8d12fa2c59967f19ccbabc18ea3b0ca3602275d' => [
			'key'        => 'e470c61ff127b87010dd8f4bd8d12fa2c59967f19ccbabc18ea3b0ca3602275d',
			'desc'       => 'Root Key #2',
			'date'       => '2020-01-01T00:00:00Z',
			'validUntil' => '2035-01-01T00:00:00Z',
			'canSign'    => [ 'key' ],
			'signature'  => []
		]
	];

	protected $key_cache = [];

	protected function __construct() {
		foreach ( $this->trusted_root_keys as $key => $data ) {
			$this->key_cache[ $key ] = $data;
		}
	}

	static $instance = false;
	public static function instance() {
		return self::$instance ?: self::$instance = new Plugin;
	}

	public function get_trusted_roots() {
		return $this->trusted_root_keys;
	}

	public function is_trusted( $key, $what = '' ) {
		$valid_whats = [ 'key', 'api', 'core', 'nightly', 'plugins', 'themes', 'translations' ];
		if ( ! in_array( $what, $valid_whats ) ) {
			return false;
		}

		// Fetch the manifest for the key, recursively.
		if ( ! isset( $this->key_cache[ $key ] ) ) {
			// Fetch key data from WordPress.org.
			$req = wp_safe_remote_get( "https://api.wordpress.org/key-manifests/{$key}.json" );
			if ( 200 === wp_remote_retrieve_response_code( $req ) ) {
				$json = json_decode( wp_remote_retrieve_body( $req ), true );
				if ( $json ) {
					// We've got a manifest, but we're not sure it's valid yet.
					$this->key_cache[ $key ] = false;

					if ( $key === $json['key'] && $this->validate_signed_json( $json ) ) {
						$this->key_cache[ $key ] = $json;
					}
				}
			}
		}

		// Not known, not found on WordPress.org, don't care :)
		if ( empty( $this->key_cache[ $key ] ) ) {
			return false;
		}

		// We know about this key, but can it sign what we want?
		return in_array( $what, $this->key_cache[ $key ]['canSign'], true );
	}

	protected function validate_signed_json( $json ) {
		$canonical_json = $this->json_canonical_encode( $json );

		if ( ! isset( $json['signature'] ) ) {
			return false;
		}

		foreach ( $json['signature'] as $key => $signature ) {
			if ( $this->is_trusted( $key, 'key' ) ) {
				if ( sodium_crypto_sign_verify_detached( hex2bin( $signature ), $canonical_json, hex2bin( $key ) ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Returns a canonicalised JSON-encoded form of the $data.
	 * 
	 * The keys are sorted in a consistent fasion, and any signature key removed.
	 */
	public function json_canonical_encode( $data ) {
		if ( is_string( $data ) && '{' === $data[0] ) {
			$data = json_decode( $data, true );
		}

		if ( ! is_array( $data ) ) {
			return false;
		}

		unset( $data['signature'] );
		ksort( $data );

		return json_encode( $data );
	}
}
Plugin::instance();
