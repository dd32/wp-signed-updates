<?php

use dd32\WordPressSignedUpdates\Plugin;

class Test_Trust extends WP_Signing_UnitTestCase {

	function test_invalid_context() {
		$key = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/api.pub' );

		$this->assertTrue( Plugin::instance()->key_is_trusted( $key ) );
		$this->assertFalse( Plugin::instance()->key_is_valid_for( $key, 'unknown-context' ) );
	}

	function test_key_expiry() {
		$key = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/expired-intermediate.pub' );

		$this->assertTrue( Plugin::instance()->key_is_trusted( $key ) );
		$this->assertTrue( Plugin::instance()->key_is_valid_for( $key, 'key' ) );
		$this->assertTrue( Plugin::instance()->key_is_valid_for_date( $key, '2020-03-01T00:00:00Z' ) );
		$this->assertTrue( Plugin::instance()->key_is_valid_for_date( $key, strtotime( '2020-03-01T00:00:00Z' ) ) );
		$this->assertFalse( Plugin::instance()->key_is_valid_for_date( $key, '2020-09-01T00:00:00Z' ) );
	}

	function test_key_expiry_invalid_key() {
		$key = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/invalid-api.pub' );

		$this->assertFalse( Plugin::instance()->key_is_trusted( $key ) );
		$this->assertFalse( Plugin::instance()->key_is_valid_for( $key, 'api' ) );
		$this->assertFalse( Plugin::instance()->key_is_valid_for_date( $key, '2025-01-01T00:00:00Z' ) );
	}

	function test_can_trust() {
		$key = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/api.pub' );

		$this->assertTrue(  Plugin::instance()->can_trust( $key, 'api', '2020-12-01T00:00:00Z' ) );
		$this->assertFalse( Plugin::instance()->can_trust( $key, 'key', '2020-12-01T00:00:00Z' ) );
		$this->assertFalse( Plugin::instance()->can_trust( $key, 'api', '2025-12-01T00:00:00Z' ) );
		$this->assertFalse( Plugin::instance()->can_trust( $key, 'key', '2025-12-01T00:00:00Z' ) );
	}

	/**
	 * @dataProvider data_find_all_key_manifest_matrix
	 */
	function test_keys_from_manifest( $key_file, $should_be_true, $should_be_false ) {
		$key = file_get_contents( SIGNING_PLUGIN_DIR . '/keys/' . $key_file );

		$this->assertTrue( Plugin::instance()->key_is_trusted( $key ) );

		foreach ( $should_be_true as $i ) {
			$this->assertTrue( Plugin::instance()->key_is_valid_for( $key, $i ) );
		}
		foreach ( $should_be_false as $i ) {
			$this->assertFalse( Plugin::instance()->key_is_valid_for( $key, $i ) );
		}
	}

	function data_find_all_key_manifest_matrix() {
		return [
			[
				'root.pub',
				[ 'key' ],
				[ 'api', 'core', 'nightly', 'plugins', 'themes', 'translations' ]
			],
			[
				'root2.pub',
				[ 'key' ],
				[ 'api', 'core', 'nightly', 'plugins', 'themes', 'translations' ]
			],
			[
				'intermediate.pub',
				[ 'key' ],
				[ 'api', 'core', 'nightly', 'plugins', 'themes', 'translations' ]
			],
			[
				'expired-intermediate.pub',
				[ 'key' ],
				[ 'api', 'core', 'nightly', 'plugins', 'themes', 'translations' ]
			],
			[
				'api.pub',
				[ 'api' ],
				[ 'key', 'core', 'nightly', 'plugins', 'themes', 'translations' ]
			],
			[
				'packages.pub',
				[ 'core', 'nightly', 'plugins', 'themes', 'translations' ],
				[ 'key', 'api' ]
			],
		];
	}
}