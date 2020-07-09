<?php
// Symfony Polyfill https://github.com/symfony/polyfill/blob/master/src/Php80/Php80.php

function str_starts_with( $haystack, $needle ) {
	 return 0 === strncmp( $haystack, $needle, strlen( $needle ) );
 }

function str_ends_with( $haystack, $needle ) {
	 return '' === $needle || ( '' !== $haystack && 0 === substr_compare( $haystack, $needle, -strlen( $needle ) ) );
 }

function str_contains( $haystack, $needle ) {
	return '' === $needle || false !== strpos($haystack, $needle );
}