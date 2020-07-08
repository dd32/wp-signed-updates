<?php

use dd32\WordPressSignedUpdates\Plugin;

class Test_Trust extends WP_Signing_UnitTestCase {
	function test_roots_are_trusted() {
		foreach ( Plugin::instance()->get_trusted_roots() as $root ) {
			$this->assertTrue( Plugin::instance()->is_trusted_key( $root, 'cert' ) );
		}
	}
}