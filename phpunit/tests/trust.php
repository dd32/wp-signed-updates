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

		$this->assertTrue( Plugin::instance()->is_trusted( $key, 'api' ) );
	}

	function test_api_key_is_trusted_to_sign_responses() {
		$key = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/api.pub' );

		$this->assertTrue( Plugin::instance()->is_trusted( $key, 'api' ) );
	}

	function test_api_key_is_not_trusted_to_sign_keys() {
		$key = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/api.pub' );

		$this->assertTrue( Plugin::instance()->is_trusted( $key, 'key' ) );
	}
}