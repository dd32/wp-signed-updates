<?php

use dd32\WordPressSignedUpdates\Plugin;

class Test_Packages extends WP_Signing_UnitTestCase {

	function test_http_manifest_exists_and_is_valid() {
		$req = wp_remote_request(
			'https://downloads.wordpress.org/plugin/hello-dolly.latest-stable.zip?nostats=1',
			[ 'stream' => true ]
		);

		$this->assertNotWPError( $req );
		$this->assertTrue( !empty( $req['headers']['link'] ), "No link header present" );
		$this->assertTrue( str_contains( $req['headers']['link'], 'rel="manifest"' ), "Manifest Link malformed. " . $req['headers']['link'] );

		$manifest_url = explode( ';', $req['headers']['link'] )[0];
		$manifest_url = trim( $manifest_url, '<>' );

		$this->assertFalse( str_contains( $manifest_url, 'latest-stable' ), "Manifest URL invalid." );

		$req = wp_remote_get( $manifest_url );

		$this->assertEquals( 200, wp_remote_retrieve_response_code( $req ), "Invalid response code." );

		$manifest = json_decode( wp_remote_retrieve_body( $req ), true );

		// Check that the API response has a valid signature.
		$this->assertTrue( Plugin::instance()->validate_signed_json( $manifest, 'api' ), "Manifest signature failed." );

		$this->assertEquals( 'plugin', $manifest['type'] );

		$this->assertGreaterThanOrEqual( 1, count( $manifest['hash'] ) );

		// Check that the hash is signed.
		foreach ( $manifest['hash'] as $hash ) {
			$this->assertTrue(
				Plugin::instance()->validate_signature( 'plugins', $hash['date'], $hash['hash'], $hash['signature'] ),
				"Hash signature failed."
			);
		}

	}
}