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

	protected const TRUSTED_KEYS = [];
	protected const VALID_DOMAINS = [ 'wordpress.org', 'downloads.wordpress.org', 's.w.org' ];

	public function __construct() {
		// Include Sodium_Compat when required.
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			include_once __DIR__ . '/sodium_compat/autoload.php';
		}

		add_action( 'upgrader_pre_download', [ $this, 'download_package_override' ], 1, 3 );
	}

	public function validate_signature( $download_file, $signature_url ) {
		$trusted_keys = apply_filters( 'wp_trusted_keys', self::TRUSTED_KEYS );

		// Fetch the signature of the file.
		// We're using detached signatures here, where it's stored in a separate file.
		$signature_request = wp_safe_remote_get( $signature_url );
		$signature = wp_remote_retrieve_body( $signature_request );
		if ( is_wp_error( $signature_request ) || ! $signature ) {
			return false;
		}

		$file_contents = file_get_contents( $download_file );

		foreach ( $trusted_keys as $key ) {
			if ( sodium_crypto_sign_verify_detached( hex2bin( $signature ), $file_contents, hex2bin( $key ) ) ) {
				return true;
			}
		}

		return false;
	}

	// Override the WP_Upgrader download_package() method to perform signature verification.
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

		$download_file = download_url( $package );

		if ( is_wp_error( $download_file ) ) {
			return new WP_Error( 'download_failed', $upgrader->strings['download_failed'], $download_file->get_error_message() );
		}

		// START SIGNING CODE

		// All signatures are available at `$url.sig`.
		$signature_url = "$package.sig";

		// Verify the Signature
		$upgrader->skin->feedback(
			'Verifying file signature&#8230; Fetching %s&#8230;',
			'<code>' . $signature_url . '</code>'
		);

		if ( ! $this->validate_signature( $download_file, $signature_url ) ) {
			@unlink( $download_file );
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

		return $download_file;
	}
}
new WP_Signing_Verify();
