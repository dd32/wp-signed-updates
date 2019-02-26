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

	/**
	 * A temporary storage map of $url => $file for files WP_HTTP creates.
	 */
	protected $downloaded_files = array();

	/**
	 * The domains whose requests we intend on signing.
	 */
	protected $valid_domains = array( 'wordpress.org', 'downloads.wordpress.org', 's.w.org' );

	/**
	 * Register filters required for this POC
	 */
	public function __construct() {
		// Include Sodium_Compat when required.
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			include_once dirname( __FILE__ ) . '/sodium_compat/autoload.php';
		}

		// Let WordPress know about OUR key
		add_filter( 'wp_trusted_keys',  array( $this, 'wp_trusted_keys' ) );

		// no-op HTTP requests for $url.sig, as we're replacing them with our own versions.
		add_filter( 'pre_http_request', array( $this, 'intercept_signature_http_request' ), 10, 3 );

		// Store the list of URLs WP_HTTP downloads to file, to allow us to sign that instead of re-requesting it.
		add_filter( 'http_response',    array( $this, 'remember_requested_files' ), 10, 3 );

		// Add a X-Content-Signature header to WP_HTTP file downloads.
		add_filter( 'http_response',    array( $this, 'add_signature_header' ), 10, 3 );
	}

	/**
	 * Filter to override the WP_HTTP requests to return our own Signature Files.
	 *
	 * @param mixed  $filter_value The download result to override.
	 * @param array  $args         The WP_HTTP Request args.
	 * @param string $url          The URL being requested.
	 * @return null|array Null if we're not affecting the request, or an array mimicking WP_HTTP with our signature upon request.
	 */
	public function intercept_signature_http_request( $filter_value, $args, $url ) {
		// Only sign specific URLs
		$hostname = parse_url( $url, PHP_URL_HOST );
		if ( ! in_array( $hostname, $this->valid_domains, true ) ) {
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

		// Intercept the request, return our new signature (Plus an extra random one which should fail)
		return array(
			'body' => $this->random_signature() . "\n" . $signature,
			'response' => array(
				'code' => 200,
				'message' => 'OK',
			),
			'headers' => array(),
			'cookies' => array(),
			'filename' => null,
		);
	}

	/**
	 * Filter WP_HTTP responses to add our X-Content-Signature header when required.
	 *
	 * @param mixed  $response  The WP_HTTP result to modify.
	 * @param array  $args      The WP_HTTP Request args.
	 * @param string $url       The URL being requested.
	 * @return mixed The WP_HTTP result, maybe with X-Content-Signature added.
	 */
	public function add_signature_header( $response, $args, $url ) {
		// Only sign specific URLs
		$hostname = parse_url( $url, PHP_URL_HOST );
		if ( ! in_array( $hostname, $this->valid_domains, true ) ) {
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
			$response['headers']['x-content-signature'] = array( $this->random_signature(), $signature );
		}

		return $response;
	}

	/**
	 * Filter WP_HTTP responses to remember downloaded files, used to make it easier to sign requests.
	 *
	 * @param mixed  $response  The WP_HTTP result to modify.
	 * @param array  $args      The WP_HTTP Request args.
	 * @param string $url       The URL being requested.
	 * @return mixed The WP_HTTP result, maybe with X-Content-Signature added.
	 */
	public function remember_requested_files( $response, $args, $url ) {
		if ( $response['filename'] ) {
			$this->downloaded_files[ $url ] = $response['filename'];
		}

		return $response;
	}

	/**
	 * Add our Signing key to WordPress's trusted keys.
	 *
	 * @param array $keys The existing trusted keys.
	 * @return $keys with an additional key.
	 */
	public function wp_trusted_keys( $keys ) {
		if ( ! get_option( 'signing_signer_public_key' ) ) {
			$this->regenerate_keys();
		}

		if ( $public_key = get_option( 'signing_signer_public_key' ) ) {
			$keys[] = $public_key;
		}

		return $keys;
	}

	/**
	 * Generate the signature for a given file.
	 *
	 * @param string $filename The file to sign.
	 * @return bool|string False upon failure, hex-encoded signature upon success.
	 */
	public function sign_file( $filename ) {
		if ( ! file_exists( $filename ) ) {
			return false;
		}

		$hash = $this->generichash_file( $filename );

		$secret_key = get_option( 'signing_signer_secret_key' );
		if ( ! $secret_key ) {
			$this->regenerate_keys();
			$secret_key = get_option( 'signing_signer_secret_key' );
		}
		$secret_key = base64_decode( $secret_key );

		$signature = sodium_crypto_sign_detached( $hash, $secret_key );

		return base64_encode( $signature );
	}

	/**
	 * Uses Libsodium's GenericHash implementation of BLAKE2b to generate a files hash.
	 *
	 * @param string $file The file to hash.
	 * @return string The Hash.
	 */
	public function generichash_file( $file ) {
		$hasher = sodium_crypto_generichash_init();

		$fp = fopen( $file, 'rb' );

		while ( ! feof( $fp ) ) {
			$buffer = fread( $fp, 8192 );
			sodium_crypto_generichash_update( $hasher, $buffer );
		}

		fclose( $fp );

		return sodium_crypto_generichash_final( $hasher );
	}

	/**
	 * Generate a random signature per pageload for testing purposes.
	 */
	public function random_signature() {
		static $signature = null;
		if ( $signature ) {
			return $signature;
		}

		$keypair = sodium_crypto_sign_keypair();
		$secret_key = sodium_crypto_sign_secretkey( $keypair );

		$signature = sodium_crypto_sign_detached( (string) microtime(), $secret_key );
		$signature = base64_encode( $signature );

		return $signature;
	}

	/**
	 * Generate a new signing keypair.
	 */
	public function regenerate_keys() {
		$keypair = sodium_crypto_sign_keypair();

		$secret_key = sodium_crypto_sign_secretkey( $keypair );
		$public_key = sodium_crypto_sign_publickey( $keypair );

		update_option( 'signing_signer_secret_key', base64_encode( $secret_key ) );
		update_option( 'signing_signer_public_key', base64_encode( $public_key ) );

		return true;
	}

}
new WP_Signing_Signer();
