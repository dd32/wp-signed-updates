<?php

class WP_Signing_Upgrader_Skin extends Automatic_Upgrader_Skin {
	function header() {}
	function footer() {}
	// Assume it's all fine and dandy when we're running in tests. We're not testing Filesystem access afterall.
	function request_filesystem_credentials( $error = false, $context = '', $allow_relaxed_file_ownership = false ) {
		return true;
	}
}
