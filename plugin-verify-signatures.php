<?php
/*
 * Plugin Name: WordPress Signing: Verify Zips
 * Plugin URI: https://github.com/dd32/wp-signed-updates
 * Description: This plugin performs client-side validation of WordPress.org ZIPs bsed on public keys.
 * Author: Dion Hulse
 * Version: 0.1
 * Author URI: https://dd32.id.au/
 */

class WP_Signing_Verify {

	/**
	 * The Public Keys we trust by default.
	 */
	protected const TRUSTED_KEYS = [];

	/**
	 * The domains whose requests we intend on signing.
	 */
	protected const VALID_DOMAINS = [ 'wordpress.org', 'downloads.wordpress.org', 's.w.org' ];

	/**
	 * Register filters required for this POC
	 */
	public function __construct() {
		// Include Sodium_Compat when required.
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			include_once __DIR__ . '/sodium_compat/autoload.php';
		}

		add_action( 'upgrader_pre_download', [ $this, 'download_package_override' ], 1, 3 );
	}

	/**
	 * Validate the signature of a file where the signature is stored at a URL.
	 *
	 * @param string $file      The file to check
	 * @param string $signature URL to a file containing a signature for $file.
	 * @return bool
	 */
	public function validate_signature_from_url( $file, $signature_url ) {
		// Fetch the signature of the file.
		$signature_request = wp_safe_remote_get( $signature_url );

		$signature = wp_remote_retrieve_body( $signature_request );

		if ( is_wp_error( $signature_request ) || ! $signature ) {
			return false;
		}

		// Validate it against known keys.
		return $this->validate_signature( $file, $signature );
	}

	/**
	 * Validate the signature of a file.
	 *
	 * @param string $file      The file to check
	 * @param string $signature The Signature to validate against.
	 * @return bool
	 */
	public function validate_signature( $file, $signature ) {
		$trusted_keys = apply_filters( 'wp_trusted_keys', self::TRUSTED_KEYS );

		// Check for an invalid-length signature passed.
		if ( SODIUM_CRYPTO_SIGN_BYTES !== strlen( hex2bin( $signature ) ) )  {
			return false;
		}

		$file_contents = file_get_contents( $file );

		foreach ( $trusted_keys as $key ) {
			if ( sodium_crypto_sign_verify_detached( hex2bin( $signature ), $file_contents, hex2bin( $key ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Filter to override the `WP_Upgrader::download_package()` method to perform Signature Verification.
	 *
	 * @param mixed       $filter_value The download result to override.
	 * @param string      $package      The package which is being installed.
	 * @param WP_Upgrader $upgrader     The WP_Upgrader instance being overridden.
	 * @return null|WP_Error|string Null if we're not affecting the request, WP_Error if an error occurs, and a string of the local package to install otherwise.
	 */
	public function download_package_override( $filter_value, $package, $upgrader ) {
		if ( ! preg_match( '!^(http|https)://!i', $package ) ) {
			return $filter_value;
		}

		// Only sign specific URLs
		$hostname = parse_url( $package, PHP_URL_HOST );
		if ( ! in_array( $hostname, self::VALID_DOMAINS, true ) ) {
			return $filter_value;
		}

		if ( empty( $package ) ) {
			return new WP_Error( 'no_package', $upgrader->strings['no_package'] );
		}

		$upgrader->skin->feedback( 'downloading_package', $package );

		// Duplicated logic from `download_url()` as we need to access the Headers of the response.

		$tmpfname = wp_tempnam( basename( parse_url( $package, PHP_URL_PATH ) ) );
		if ( ! $tmpfname ) {
			return new WP_Error( 'download_failed', $upgrader->strings['download_failed'], __( 'Could not create Temporary file.' ) );
		}

		$download_request = wp_safe_remote_get(
			$package,
			array(
				'timeout'  => 300,
				'stream'   => true,
				'filename' => $tmpfname,
			)
		);

		if ( is_wp_error( $download_request ) ) {
			unlink( $tmpfname );
			return new WP_Error( 'download_failed', $upgrader->strings['download_failed'], $download_request->get_error_message() );
		}

		if ( 200 != wp_remote_retrieve_response_code( $download_request ) ) {
			unlink( $tmpfname );
			return new WP_Error( 'download_failed', $upgrader->strings['download_failed'], wp_remote_retrieve_response_message( $download_request ) );
		}

		// End duplicated logic from `download_url()`.

		// START SIGNING CODE

		$signature = wp_remote_retrieve_header( $download_request, 'x-content-signature' );
		if ( $signature ) {
			// Verify the Signature
			$upgrader->skin->feedback( 'Verifying file signature from HTTP Header&#8230;' );

			$signature_valid = $this->validate_signature( $download_request['filename'], $signature );
		} else {
			// Fetch a detached signature from `$url.sig` and validate it.
			$signature_url = "$package.sig";
			$upgrader->skin->feedback(
				'Verifying file signature&#8230; Fetching %s&#8230;',
				'<code>' . $signature_url . '</code>'
			);

			$signature_valid = $this->validate_signature_from_url( $download_request['filename'], $signature_url );
		}

		if ( ! $signature_valid ) {
			unlink( $tmpfname );
			$upgrader->skin->feedback( '<strong>' . 'Signature Validation Failed.' . '</strong>' );
			return new WP_Error(
				'signature_failure',
				sprintf(
					'The signature validation of %s failed.',
					'<code>' . basename( $package ) . '</code>'
				)
			);
		}

		$upgrader->skin->feedback(
			'<strong>' . 'Signature Verification of %s Passed.' . '</strong>',
			'<code>' . basename( $package ) . '</code>'
		);

		// END SIGNING CODE

		return $tmpfname;
	}
}
new WP_Signing_Verify();
