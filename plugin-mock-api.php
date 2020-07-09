<?php
namespace dd32\WordPressSignedUpdates\MockAPI;
use dd32\WordPressSignedUpdates\Plugin as VerificationPlugin;
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

	public $downloaded_file_hashes = [];

	protected function __construct() {
		add_filter( 'pre_http_request', [ $this, 'intercept' ], 10, 3 );
		add_filter( 'http_response', [ $this, 'alter_response' ], 10, 3 );
	}

	static $instance = false;
	public static function instance() {
		return self::$instance ?: self::$instance = new Plugin;
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

		if ( 'downloads.wordpress.org' === $url_parts['host'] ) {
			if (
				str_starts_with( $url_parts['path'], '/file-manifests/' ) &&
				str_ends_with( $url_parts['path'], '.json' )
			) {
				$file = basename( $url_parts['path'], '.json' );
				$type = explode( '/', $url_parts['path'] )[2];

				return $this->mock_http_response( $this->generate_file_manifest_payload( $type, $file ) );
			}
		}

		return $filter_value;
	}

	public function alter_response( $response, $parsed_args, $url ) {
		$url_parts = wp_parse_url( $url );

		if ( 'downloads.wordpress.org' === $url_parts['host'] ) {
			if (
				str_ends_with( $url_parts['path'], '.zip' )
			) {
				$type = explode( '/', $url_parts['path'] )[1];
				$file = basename( $url_parts['path'] );

				// Check the Content-Disposition for the canonical name.
				if ( str_contains( $response['headers']['content-disposition'], 'filename=' ) ) {
					$file = explode( 'filename=', $response['headers']['content-disposition'] )[1];
				}

				$file = basename( $file, '.zip' );

				$manifest_url = 'https://downloads.wordpress.org/file-manifests/' . $type . '/' . $file . '.json';
				$response['headers']['link'] = "<$manifest_url>; rel=\"manifest\"";

				if ( $response['filename'] ) {
					$this->downloaded_file_hashes[ $file ] = hash_file( 'sha384', $response['filename'], true );
				} else {
					$this->downloaded_file_hashes[ $file ] = hash( 'sha384', $response['body'], true );
				}
			}
		}

		return $response;
	}

	public function generate_manifest_payload( $key ) {
		foreach ( glob( __DIR__ . '/keys/*.json' ) as $file ) {
			$data = json_decode( $json = file_get_contents( $file ), true );
			if ( $data && isset( $data['key'] ) && $key === $data['key'] ) {
				return $json;
			}
		}

		return false;
	}

	public function generate_file_manifest_payload( $type, $file ) {
		$zip_signing_key = $this->find_key_for( $type );
		if ( ! $zip_signing_key ) {
			// Plural...
			$zip_signing_key = $this->find_key_for( $type . 's' );
		}
		$api_signing_key = $this->find_key_for( 'api' );

		if ( ! isset( $this->downloaded_file_hashes[ $file ] ) ) {
			return false;
		}

		$sha384_hash = [
			'type'      => 'sha384',
			'hash'      => bin2hex( $this->downloaded_file_hashes[ $file ] ),
			'date'      => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'signature' => [
				$zip_signing_key['key'] => sodium_crypto_sign_detached(
					$this->downloaded_file_hashes[ $file ],
					hex2bin( $zip_signing_key['privkey'] )
				)
			]
		];

		$json = [
			'file'      => $file . '.zip',
			'type'      => $type,
			'date'      => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'version'   => explode( '.', basename( $file ), 2 )[1],
			'hash'      => [ $sha384_hash ],
			'signature' => [ $api_signing_key['key'] => '' ],
		];

		// Sign the file manifest.
		$json_canonical = VerificationPlugin::instance()->json_canonical_encode( $json );
		$json['signature'][ $api_signing_key['key'] ] = sodium_crypto_sign_detached(
			$json_canonical,
			hex2bin( $api_signing_key['privkey'] )
		);

		return json_encode( $json );
	}

	public function find_key_for( $what ) {
		foreach ( glob( __DIR__ . '/keys/*.json' ) as $file ) {
			$data = json_decode( $json = file_get_contents( $file ), true );
			if ( $data && isset( $data['key'] ) ) {
				if ( VerificationPlugin::instance()->can_trust( $data['key'], $what, time() ) ) {
					$data['privkey'] = file_get_contents( __DIR__ . '/keys/' . basename( $file, '.json' ) . '.priv' );
					return $json;
				}
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
