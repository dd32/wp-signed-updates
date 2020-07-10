<?php
namespace dd32\WordPressSignedUpdates;

//if ( $argc < 3 ) {
//	die( "Usage: $argv[0] key-to-sign key-to-sign-with\n");
//}

include __DIR__ . '/plugin.php';
include dirname( dirname(dirname( __DIR__ ) ) ) . '/wp-load.php';

$signing_key     = file_Get_contents( __DIR__ . '/keys/root.priv' );
$signing_key_pub = bin2hex( sodium_crypto_sign_publickey_from_secretkey( hex2bin( $signing_key ) ) );


$revoke = json_decode( file_get_contents( __DIR__ . '/keys/revocation-list.json' ), true );
$revoke['date'] = gmdate( 'Y-m-d\TH:i:s\Z' );
$revoke['serial']++;

$revoke_canonical = Plugin::instance()->json_canonical_encode( $revoke );

$revoke['signature'][ $signing_key_pub ] = bin2hex( sodium_crypto_sign_detached( $revoke_canonical, hex2bin( $signing_key ) ) );

file_put_contents( __DIR__ . '/keys/revocation-list.json', json_encode( $revoke, JSON_PRETTY_PRINT ) );
