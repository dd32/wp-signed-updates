<?php
/**
 * PHPUnit bootstrap file for WP Signed Updates
 *
 * @package Sample_Plugin
 */

$_tests_dir = getenv( 'WP_TESTS_DIR' );

// Check if we're installed in a src checkout.
if ( ! $_tests_dir && false !== ( $pos = stripos( __FILE__, '/src/wp-content/plugins/' ) ) ) {
	$_tests_dir = substr( __FILE__, 0, $pos ) . '/tests/phpunit/';
}

if ( ! $_tests_dir ) {
	$_tests_dir = rtrim( sys_get_temp_dir(), '/\\' ) . '/wordpress-tests-lib';
}

if ( ! file_exists( $_tests_dir . '/includes/functions.php' ) ) {
	echo "Could not find $_tests_dir/includes/functions.php\n";
	exit( 1 );
}

// Give access to tests_add_filter() function.
require_once $_tests_dir . '/includes/functions.php';

/**
 * Manually load the plugins.
 */
function _manually_load_signing_plugins() {
	require_once dirname( dirname( __FILE__ ) ) . '/plugin.php';
	require_once dirname( dirname( __FILE__ ) ) . '/plugin-mock-api.php';
}
tests_add_filter( 'plugins_loaded', '_manually_load_signing_plugins' );

// Start up the WP testing environment.
require $_tests_dir . '/includes/bootstrap.php';
