<?php
/*
 * Plugin Name: WordPress Signing: Sign w.org ZIPs
 * Plugin URI: https://github.com/dd32/wp-signed-updates
 * Description: This plugin performs client-side signing of WordPress-served ZIP files, it's intended to allow local development, and test the process of generating signatures.
 * Author: Dion Hulse
 * Version: 0.1
 * Author URI: https://dd32.id.au/
 */

class WP_Signing_Signer {
	protected $downloaded_files = [];
	protected const VALID_DOMAINS = [ 'wordpress.org', 'downloads.wordpress.org', 's.w.org' ];

	public function __construct() {
		// Include Sodium_Compat when required.
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			include_once __DIR__ . '/sodium_compat/autoload.php';
		}

		add_filter( 'wp_trusted_keys',  [ $this, 'wp_trusted_keys' ] );
		add_filter( 'pre_http_request', [ $this, 'intercept_signature_http_request' ], 10, 3 );
		add_filter( 'http_response',    [ $this, 'remember_requested_files' ], 10, 3 );
		add_filter( 'http_response',    [ $this, 'add_signature_header' ], 10, 3 );
	}

	public function intercept_signature_http_request( $filter_value, $args, $url ) {
		// Only sign specific URLs
		$hostname = parse_url( $url, PHP_URL_HOST );
		if ( ! in_array( $hostname, self::VALID_DOMAINS, true ) ) {
			return $filter_value;
		}

		// Only intercept requests for file signatures
		if ( ! preg_match( '!^(.+)\.sig$!i', $url, $matches ) ) {
			return $filter_value;
		}
		$file_url = $matches[1];

		if ( ! isset( $this->downloaded_files[ $file_url ] ) ) {
			return $filter_value;
		}

		$signature = $this->sign_file( $this->downloaded_files[ $file_url ] );

		// Abort.
		if ( ! $signature ) {
			return $filter_value;
		}

		// Intercept the request, return our new signature.
		return [
			'body' => $signature,
			'response' => [
				'code' => 200,
				'message' => 'OK',
			],
			'headers' => [],
			'cookies' => [],
			'filename' => null,
		];
	}

	public function add_signature_header( $response, $args, $url ) {
		// Only sign specific URLs
		$hostname = parse_url( $url, PHP_URL_HOST );
		if ( ! in_array( $hostname, self::VALID_DOMAINS, true ) ) {
			return $response;
		}

		// Only sign streamed files
		if ( ! $response['filename'] ) {
			return $response;
		}

		// Only sign ZIPs for now.
		if ( ! preg_match( '!\.zip!i', $url ) ) {
			return $response;
		}

		// Sign it.
		$signature = $this->sign_file( $response['filename'] );
		if ( $signature ) {
			$response['headers']['x-content-signature'] = $signature;
		}

		return $response;
	}

	// Remember the downloaded files to allow us to use the local file for signing.
	public function remember_requested_files( $response, $args, $url ) {
		if ( $response['filename'] ) {
			$this->downloaded_files[ $url ] = $response['filename'];
		}

		return $response;
	}

	// Add our public key to WordPress.
	public function wp_trusted_keys( $keys ) {
		if ( ! get_option( 'signing_signer_public_key' ) ) {
			$this->regenerate_keys();
		}

		if ( $public_key = get_option( 'signing_signer_public_key' ) ) {
			$keys[] = $public_key;
		}

		return $keys;
	}

	// Sign a file.
	public function sign_file( $filename ) {
		if ( ! file_exists( $filename ) ) {
			return false;
		}
		$file_contents = file_get_contents( $filename );
		if ( ! $file_contents ) {
			return false;
		}

		$secret_key = get_option( 'signing_signer_secret_key' );
		if ( ! $secret_key ) {
			$this->regenerate_keys();
			$secret_key = get_option( 'signing_signer_secret_key' );
		}
		$secret_key = hex2bin( $secret_key );

		$signature = sodium_crypto_sign_detached( $file_contents, $secret_key );

		return bin2hex( $signature );
	}

	// Generate a keypair for signing, not stored securely.
	public function regenerate_keys() {
		$keypair = sodium_crypto_sign_keypair();

		$secret_key = sodium_crypto_sign_secretkey( $keypair );
		$public_key = sodium_crypto_sign_publickey( $keypair );

		update_option( 'signing_signer_secret_key', bin2hex( $secret_key ) );
		update_option( 'signing_signer_public_key', bin2hex( $public_key ) );

		return true;
	}
}
new WP_Signing_Signer();
