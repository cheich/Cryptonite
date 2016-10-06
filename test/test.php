<?php

use Cryptonite\SymmetricEncryption;
use Cryptonite\AsymmetricEncryption;
use Cryptonite\Password;
use Cryptonite\EncryptionException;

require '../Cryptonite.php';

//
// Some phrases
//

$string    = 'This is my secret string';
$pass      = 'A strong password';
$wrongPass = 'Wrong password';

echo '<pre>';
echo "<h1>Cryptonite - the hacker's kryptonite</h1>";

var_dump($string);
echo PHP_EOL;
var_dump($pass);
echo PHP_EOL;
var_dump($wrongPass);

try {

  //
  // Symmetric encryption
  //

  echo '<h2>Symmetric encryption</h2>';

  $symmetric = new SymmetricEncryption();
  $encrypted = $symmetric->encrypt($string, $pass);

  echo '<h3>Encrypted (Base64 encoded)</h3>';
  var_dump(base64_encode($encrypted));

  echo '<h3>IV (Base64 encoded)</h3>';
  echo '<p>New IV each encryption; can be public</p>';
  var_dump(base64_encode($symmetric->getInitVector()));

  echo '<h3>Decrypted</h3>';
  var_dump($symmetric->decrypt($encrypted, $pass, $symmetric->getInitVector()));

  echo '<h3>Decrypted (wrong password)</h3>';
  var_dump($symmetric->decrypt($encrypted, 'asd', $symmetric->getInitVector()));


  //
  // Asymmetric encryption
  //

  echo '<h2>Asymmetric encryption</h2>';

  $asymmetric = new AsymmetricEncryption();

  $publicKey = $asymmetric->getPublicKey();
  $privateKey = $asymmetric->getPrivateKey($pass);

  $encrypted = $asymmetric->encrypt($string, $publicKey);

  echo '<h3>Encrypted (Base64 encoded)</h3>';
  var_dump(base64_encode($encrypted));

  echo '<h3>Decrypted</h3>';
  var_dump($asymmetric->decrypt($encrypted, $privateKey, $pass));

  echo '<h3>Decrypted (wrong password)</h3>';
  var_dump($asymmetric->decrypt($encrypted, $privateKey, $wrongPass));

  echo '<h3>Public Key</h3>';
  var_dump($asymmetric->getPublicKey());

  echo '<h3>Private Key</h3>';
  echo '<p>Encrypted with password</p>';
  var_dump($privateKey);


  //
  // Passwords
  //

  echo '<h2>Passwords</h2>';

  $password = new Password();
  $hashed = $password->hash($pass);

  echo '<h3>Hashed</h3>';
  var_dump($hashed);

  echo '<h3>Verify (passed)</h3>';
  var_dump($password->verify($pass, $hashed));

  echo '<h3>Verify (wrong)</h3>';
  var_dump($password->verify($wrongPass, $hashed));

} catch (EncryptionException $e) {
  echo '<h2>Something went wrong</h2>';
  echo "<p>{$e->getMessage()}</p>";
}

echo '</pre>';
