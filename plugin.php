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
		'39f6eb7cd5c98ff9244dc8489a1f9f793510c456a9e2a8349319e18808136634', // Root 1
		'e470c61ff127b87010dd8f4bd8d12fa2c59967f19ccbabc18ea3b0ca3602275d', // Root 2
	];

	protected $key_cache = [];

	protected function __construct() {
	}

	static $instance;
	public static function instance() {
		return self::$instance ?? self::$instance = new Plugin;
	}

	public function get_trusted_roots() {
		return $this->trusted_root_keys;
	}

	public function is_trusted( $key, $what = '' ) {
		$valid_whats = [ 'key', 'api', 'core', 'plugins', 'themes', 'translations' ];
		if ( ! in_array( $what, $valid_whats ) ) {
			return false;
		}

		// Does key look base64 encoded?
		if ( preg_match( '![^a-f0-9]!', $key ) ) {
			$key = bin2hex( base64_decode( $key ) );
		}

		// Roots are always trusted for a key.
		if ( 'key' === $what && in_array( $key, $this->trusted_root_keys ) ) {
			return true;
		}

		// Fetch the manifest for the key, recursively.
		if ( ! isset( $this->key_cache[ $key ] ) ) {
			// Fetch key data from WordPress.org.
			$req = wp_safe_remote_get( "https://api.wordpress.org/key-manifest/{$key}.json" );
			echo "Fetching https://api.wordpress.org/key-manifest/{$key}.json ";
			if ( ! is_wp_error( $req ) && 200 == wp_remote_retrieve_response_code( $req ) ) {
				$json = json_decode( wp_remote_retrieve_body( $req ) );
				if ( $json && $this->validate_signed_json( $json ) ) {
					$this->key_cache[ $key ] = $json;
				}
			}
			echo wp_remote_retrieve_response_code( $req ) . "\n";
		}

		// Not known, not found on WordPress.org, don't care :)
		if ( ! isset( $this->key_cache[ $key ] ) ) {
			return false;
		}

		// We know about this key, but can it sign what we want?
		return in_array( $what, $this->key_cache[ $key ]['canSign'], true );
	}

	protected function validate_signed_json( $json ) {
		$canonical_json = $this->json_canonical_encode( $json );

		foreach ( $json['signatures'] as $key => $signature ) {
			if ( $this->is_trusted( $key, 'key' ) ) {
				if ( sodium_crypto_sign_verify_detached( hex2bin( $signature ), $canonical_json ) ) {
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
