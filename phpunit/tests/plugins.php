<?php

class Test_Plugins extends WP_Signing_UnitTestCase {

	// Integration test - Install a plugin, see if signature verification occurs and passes.
	function test_install_plugin() {

		$messages = $this->install_plugin_and_return_messages( 'hello-dolly' );

		// Verify that signing is being attempted.
		$verify = false;
		foreach ( $messages as $msg ) {
			$verify = $verify || ( false !== stripos( $msg, 'Verifying file signature' ) );
		}
		$this->assertTrue( $verify, "Signature Verification did not occur" );

		// Verify that Signature passed.
		$signature_passed = false;
		foreach ( $messages as $msg ) {
			$signature_passed = $signature_passed || preg_match( '!Signature Verification of .+ Passed!i', $msg );
		}
		$this->assertTrue( $signature_passed, "Signature Verification Failed" );

	}

	// Integration test - Install a plugin, ensure signature verification fails with no keys.
	function test_install_plugin_failure_with_no_keys() {

		add_filter( 'wp_trusted_keys', '__return_empty_array', 100 );

		$messages = $this->install_plugin_and_return_messages( 'hello-dolly' );

		// Verify that signing is being attempted.
		$verify = false;
		foreach ( $messages as $msg ) {
			$verify = $verify || ( false !== stripos( $msg, 'Verifying file signature' ) );
		}
		$this->assertTrue( $verify, "Signature Verification did not occusr" );

		// Verify that Signature failed.
		$signature_failure = false;
		foreach ( $messages as $msg ) {
			$signature_failure = $signature_failure || ( false !== stripos( $msg, 'Signature Validation Failed' ) );
		}
		$this->assertTrue( $signature_failure, "Signature Verification Failed" );

		remove_filter( 'wp_trusted_keys', '__return_empty_array', 100 );

	}

	// Integration test - Install a plugin, ensure signature verification fails with an invalid key
	function test_install_plugin_failure_with_invalid_keys() {

		add_filter( 'wp_trusted_keys', array( $this, 'filter_wp_trusted_keys_only_invalid_key' ), 100 );

		$messages = $this->install_plugin_and_return_messages( 'hello-dolly' );

		// Verify that signing is being attempted.
		$verify = false;
		foreach ( $messages as $msg ) {
			$verify = $verify || ( false !== stripos( $msg, 'Verifying file signature' ) );
		}
		$this->assertTrue( $verify, "Signature Verification did not occusr" );

		// Verify that Signature failed.
		$signature_failure = false;
		foreach ( $messages as $msg ) {
			$signature_failure = $signature_failure || ( false !== stripos( $msg, 'Signature Validation Failed' ) );
		}
		$this->assertTrue( $signature_failure, "Signature Verification Failed" );

		remove_filter( 'wp_trusted_keys', array( $this, 'filter_wp_trusted_keys_only_invalid_key' ), 100 );

	}

	// Integration Test - Install a plugin, ensure signature verification succeeds even though there's an invalid key trusted by WordPress.
	function test_install_plugin_passes_with_prefixed_invalid_key() {

		add_filter( 'wp_trusted_keys', array( $this, 'filter_wp_trusted_keys_prefix_invalid_key' ), 100 );

		$messages = $this->install_plugin_and_return_messages( 'hello-dolly' );

		// Verify that signing is being attempted.
		$verify = false;
		foreach ( $messages as $msg ) {
			$verify = $verify || ( false !== stripos( $msg, 'Verifying file signature' ) );
		}
		$this->assertTrue( $verify, "Signature Verification did not occusr" );

		// Verify that Signature passed.
		$signature_passed = false;
		foreach ( $messages as $msg ) {
			$signature_passed = $signature_passed || preg_match( '!Signature Verification of .+ Passed!i', $msg );
		}
		$this->assertTrue( $signature_passed, "Signature Verification Failed" );

		remove_filter( 'wp_trusted_keys', array( $this, 'filter_wp_trusted_keys_prefix_invalid_key' ), 100 );
	}

	// Integration Test - Ensure that installing a plugin from a non-WordPress.org location bypasses signature verification.
	function test_install_plugin_3rd_party_bypasses_signing() {
		$url = 'https://github.com/dd32/wp-signed-updates/archive/master.zip';

		$messages = $this->install_plugin_and_return_messages( $url );

		// Verify that signing is NOT being attempted.
		$verify = false;
		foreach ( $messages as $msg ) {
			$verify = $verify || ( false !== stripos( $msg, 'Verifying file signature' ) );
		}
		$this->assertFalse( $verify, "Signature Verification occured, it shouldn't have!" );
	}

}