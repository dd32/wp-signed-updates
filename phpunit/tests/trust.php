<?php

use dd32\WordPressSignedUpdates\Plugin;

class Test_Trust extends WP_Signing_UnitTestCase {

	function test_roots_are_trusted() {
		$root_one = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/root.pub' );
		$root_two = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/root2.pub' );

		$this->assertTrue( Plugin::instance()->is_trusted( $root_one, 'key' ) );
		$this->assertTrue( Plugin::instance()->is_trusted( $root_two, 'key' ) );
		$this->assertFalse( Plugin::instance()->is_trusted( $root_one . $root_two, 'key' ) );
	}
	function test_root_is_not_trusted_to_sign_responses() {
		$key = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/root.pub' );

		$this->assertFalse( Plugin::instance()->is_trusted( $key, 'api' ) );
	}

	function test_unknown_key_is_untrusted() {
		$key = bin2hex( wp_generate_password() );

		$this->assertFalse( Plugin::instance()->is_trusted( $key, 'api' ) );
		$this->assertFalse( Plugin::instance()->is_trusted( $key, 'key' ) );
		$this->assertFalse( Plugin::instance()->is_trusted( $key, 'core' ) );
	}

	function test_intermediate_is_trusted() {
		$key = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/intermediate.pub' );

		$this->assertTrue( Plugin::instance()->is_trusted( $key, 'key' ) );
	}

	function test_intermediate_is_not_trusted_to_sign_responses() {
		$key = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/intermediate.pub' );

		$this->assertFalse( Plugin::instance()->is_trusted( $key, 'api' ) );
	}

	function test_api_key_is_trusted_to_sign_responses() {
		$key = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/api.pub' );

		$this->assertTrue( Plugin::instance()->is_trusted( $key, 'api' ) );
	}

	function test_api_key_is_not_trusted_to_sign_keys() {
		$key = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/api.pub' );

		$this->assertFalse( Plugin::instance()->is_trusted( $key, 'key' ) );
	}

	function test_packages_key_is_trusted_to_sign_zips() {
		$key = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/packages.pub' );

		$this->assertTrue( Plugin::instance()->is_trusted( $key, 'core' ) );
		$this->assertTrue( Plugin::instance()->is_trusted( $key, 'api' ) );
		$this->assertTrue( Plugin::instance()->is_trusted( $key, 'api' ) );
	}

	/**
	 * @dataProvider data_find_all_key_manifest_matrix
	 */
	function test_keys_from_manifest( $key, $should_be_true, $should_be_false ) {
		foreach ( $should_be_true as $i ) {
			$this->assertTrue( Plugin::instance()->is_trusted( $key, $i ) );
		}
		foreach ( $should_be_false as $i ) {
			$this->assertFalse( Plugin::instance()->is_trusted( $key, $i ) );
		}
	}

	function data_find_all_key_manifest_matrix() {
		$known_types = [ 'key', 'api', 'core', 'plugins', 'themes', 'translations' ];

		$return = [];

		foreach ( glob( SIGNING_PLUGIN_DIR . '/keys/*.json' ) as $json_file ) {
			$base = explode( '.', $file )[0];

			$json = json_decode( file_get_contents( $base . '.json' ), true );
			$pub_key = file_get_contents( $base . '.pub' );

			$return[] = [
				$pub_key,
				$json['canSign'],
				array_diff( $known_types, $json['canSign'] )
			];

		}

		return $return;
	}
}