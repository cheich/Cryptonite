<?php

use Cheich\Cryptonite\SymmetricEncryption;
use Cheich\Cryptonite\AsymmetricEncryption;
use Cheich\Cryptonite\Password;
use Cheich\Cryptonite\EncryptionException;

require '../src/Encryption.php';
require '../src/EncryptionException.php';
require '../src/SymmetricEncryption.php';
require '../src/AsymmetricEncryption.php';
require '../src/Password.php';

//
// Some phrases
//

$string      = 'This is my secret string';
$pass        = 'A strong password';
$privateFile = dirname(__FILE__).'/private.key';
$publicFile  = dirname(__FILE__).'/public.key';

echo '<pre>';
echo "<h1>Cryptonite - the hacker's kryptonite</h1>";

var_dump($string);
echo PHP_EOL;
var_dump($pass);
echo PHP_EOL;
var_dump($privateFile);
echo PHP_EOL;
var_dump($publicFile);

try {

  //
  // Asymmetric encryption
  //

  echo '<h2>Get/export keys from asymmetric encryption</h2>';

  $asymmetric = new AsymmetricEncryption();

  // echo '<h3>Private key</h3>';
  // var_dump($asymmetric->getPrivateKey($pass));

  // echo '<h3>Public key</h3>';
  // var_dump($asymmetric->getPublicKey());

  echo '<h3>Export to file</h3>';
  echo '<p><a href="?export=1">Test export to file...</a></p>';
  echo "<p>This should generate two files.</p>";

  if (isset($_GET['export']) && $_GET['export']) {
    $encrypted = $asymmetric->exportPrivateKey($privateFile, $pass);
    $encrypted = $asymmetric->exportPublicKey($publicFile);

    if (file_exists($privateFile) && file_exists($publicFile)) {
      echo '<p>Exporting to file succeeded!</p>';
    }
  }

} catch (EncryptionException $e) {
  echo '<h2>Something went wrong</h2>';
  echo "<p>{$e->getMessage()}</p>";
}

echo '</pre>';
