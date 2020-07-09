<?php
namespace dd32\WordPressSignedUpdates;

if ( $argc < 3 ) {
	die( "Usage: $argv[0] key-to-sign key-to-sign-with\n");
}

include __DIR__ . '/plugin.php';

list( , $key_to_sign_file, $signing_key ) = $argv;

$signing_key     = file_get_contents( $signing_key );
$signing_key_pub = bin2hex( sodium_crypto_sign_publickey_from_secretkey( hex2bin( $signing_key ) ) );

$key_to_sign_base = explode( '.', $key_to_sign_file, 2 )[0];
// Create a new keyset.
if ( ! file_exists( $key_to_sign_base . '.pub' ) ) {
	// Generate a new keyset.
	$keypair = sodium_crypto_sign_keypair();
	file_put_contents( $key_to_sign_base . '.priv', bin2hex( sodium_crypto_sign_secretkey( $keypair ) ) );
	file_put_contents( $key_to_sign_base . '.pub', $pub_key = bin2hex( sodium_crypto_sign_publickey( $keypair ) ) );
	file_put_contents( $key_to_sign_base . '.json', json_encode( array(
		'key'  => $pub_key,
		'desc' => 'Key Description Here Please',
		'date' => gmdate( 'Y-m-d\TH:i:s\Z' ),
		'validUntil' => gmdate( 'Y-m-d\TH:i:s\Z', strtotime( '+5 years' ) ),
		'canSign' => [ 'Please Change this', 'Please verify validUntil.' ],
		'signature' => [ $signing_key_pub => 'Not Yet Signed' ]
	), JSON_PRETTY_PRINT ) );

	die( "New Key " . basename( $key_to_sign_base ) . " Created. Please update " . basename( $key_to_sign_base ) . ".json before running again.\n" );
}

$signed_json_file = $key_to_sign_base . '.json';
$json = json_decode( file_get_contents( $signed_json_file ), true );

if ( ! $json ) {
	die( "Malformed $signed_json_file manifest." );
}

$canonical_json = Plugin::instance()->json_canonical_encode( $json );

$json['signature'][ $signing_key_pub ] = bin2hex( sodium_crypto_sign_detached( $canonical_json, hex2bin( $signing_key ) ) );

file_put_contents( $signed_json_file, json_encode( $json, JSON_PRETTY_PRINT ) );
