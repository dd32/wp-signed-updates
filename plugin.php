<?php
namespace dd32\WordPressSignedUpdates;
/*
 * Plugin Name: WordPress Signing, 2020
 * Plugin URI: https://github.com/dd32/wp-signed-updates
 * Description: This plugin does stuff. Client-side stuff.
 * Author: Dion Hulse
 * Version: 0.2
 * Author URI: https://dd32.id.au/
 */

class Plugin {

	protected $trusted_root_keys = [
		'OfbrfNXJj/kkTchImh+feTUQxFap4qg0kxnhiAgTZjQ=', // Root 1
		'5HDGH/EnuHAQ3Y9L2NEvosWZZ/Gcy6vBjqOwyjYCJ10=', // Root 2
	];

	protected function __construct() {
	}

	static $instance;
	public static function instance() {
		return self::$instance ?? self::$instance = new Plugin;
	}

	public function get_trusted_roots() {
		return $this->trusted_root_keys;
	}

	public function is_trusted( $key, $what ) {
		return true;
	}

}
Plugin::instance();
