
<?php  
//need to install openssl ext

function testaes256(){
	$key = "78B31088F0E44A86B749429D9F774AA0"; // 32字节密钥
	$method = "aes-256-cbc";
	$str = "www.ctrip.com1234"; // 明文

	$iv = openssl_random_pseudo_bytes(16);

	$enc = openssl_encrypt($str, $method, $key, OPENSSL_RAW_DATA, $iv);
	$cipher = $iv.$enc;

	$base64Str = base64_encode($cipher);
	echo "encrypted: $base64Str<br />";

	$dec = openssl_decrypt($enc, $method, $key, OPENSSL_RAW_DATA, $iv);
	echo "decrypted: $dec<br />";
}

function testsha256(){
	$str = "www.ctrip.com"; // 明文
	$hstr = base64_encode(hash("sha256", $str, true));
	echo "hash value: $hstr<br />";
}

function testpbkdf2(){
	$salt = openssl_random_pseudo_bytes(8);

	$str1 = "password01!";

	$pbstr = base64_encode(hash_pbkdf2("sha1", $str1, $salt, 1024, 16, true));

	$saltStr = base64_encode($salt);
	echo "pbkdf2 salt:	$saltStr<br />";
	echo "pbkdf2 value:	$pbstr<br />";
}

function testrsa(){
	$config = array(
	  //  "digest_alg" => "sha256",
	    "private_key_bits" => 2048,
	    "private_key_type" => OPENSSL_KEYTYPE_RSA,
	);
	    
	// Create the private and public key
	$res = openssl_pkey_new($config);

	// Extract the private key from $res to $privKey
	openssl_pkey_export($res, $privKey);

	// Extract the public key from $res to $pubKey
	$pubKey = openssl_pkey_get_details($res);
	$pubKey = $pubKey["key"];

	$data = 'www.ctrip.com';
	echo "plaintext:	$data<br />";

	// Encrypt the data to $encrypted using the public key
	openssl_public_encrypt($data, $encrypted, $pubKey);

	$cipher = base64_encode($encrypted);
	
	
	openssl_public_encrypt($data, $encrypted, $pubKey);

	$cipher = base64_encode($encrypted);
	
	echo "encrypted: $cipher<br />";
	// Decrypt the data using the private key and store the results in $decrypted
	openssl_private_decrypt($encrypted, $decrypted, $privKey);

	echo "decrypted: $decrypted<br />";
}

function testsign(){
	//data you want to sign
	$data = '1234567890abcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+';
	echo "data to sign: $data<br />";

	$config = array(
	  //  "digest_alg" => "sha256",
	    "private_key_bits" => 2048,
	    "private_key_type" => OPENSSL_KEYTYPE_RSA,
	);
	    
	// Create the private and public key
	$res = openssl_pkey_new($config);

	// Extract the private key from $res to $privKey
	openssl_pkey_export($res, $privKey);

	// Extract the public key from $res to $pubKey
	$pubKey = openssl_pkey_get_details($res);
	$pubKey = $pubKey["key"];

	//create signature
	openssl_sign($data, $signature, $privKey, OPENSSL_ALGO_SHA256);
	
	$sign_base64 = base64_encode($signature);
	echo "signature: $sign_base64<br />";

	//verify signature
	$r = openssl_verify($data, $signature, $pubKey, OPENSSL_ALGO_SHA256);
	echo "verifySign: $r<br />";	
}

// Demo
testaes256();
echo "<br />";	
testsha256();
echo "<br />";	
testpbkdf2();
echo "<br />";	
testrsa();
echo "<br />";	
testsign();

?>
