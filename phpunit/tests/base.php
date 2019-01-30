<?php

abstract class WP_Signing_UnitTestCase extends WP_UnitTestCase {
	// This might not actually install the plugin, as it may already exist.
	// We're not interested in actually installing the plugin though, just the steps prior to the install.
	function install_plugin_and_return_messages( $plugin_slug ) {
		include_once( ABSPATH . 'wp-admin/includes/plugin-install.php' ); // For plugins_api()
		include_once( ABSPATH . 'wp-admin/includes/class-wp-upgrader.php' ); // For Plugin_Upgrader
		include_once( dirname( dirname( __FILE__ ) ) . '/class-wp-signing-upgrader-skin.php' ); // For WP_Signing_Upgrader_Skin

		$api = plugins_api( 'plugin_information', array( 'slug' => $plugin_slug ) );

		// Temporary error
		if ( is_wp_error( $api ) ) {
			wp_die( $api );
		}

		$skin     = new WP_Signing_Upgrader_Skin();
		$upgrader = new Plugin_Upgrader( $skin );

		$upgrader->install( $api->download_link );

		return $skin->get_upgrade_messages();
	}
}
