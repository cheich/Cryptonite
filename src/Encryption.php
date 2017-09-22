<?php

/**
 * @package Cryptonite
 * @since   2.0.0
 */
namespace Cryptonite;

/**
 * Encryption
 *
 * @package Cryptonite
 */
class Encryption {
  /**
   * Required PHP version
   *
   * @var string
   */
  const REQUIRED_PHP_VERSION = '5.3.3';

  /**
   * Required OpenSSL version
   *
   * @var hex
   */
  const REQUIRED_OPENSSL_VERSION = 0x00090600f;

  /**
   * Hash method
   *
   * @var string
   */
  protected $hashMethod = 'sha256';

  /**
   * Constructor
   *
   * @throws EncryptionException
   */
  public function __construct() {
    // Check used PHP version
    if (version_compare(PHP_VERSION, self::REQUIRED_PHP_VERSION, '<')) {
      throw new EncryptionException('Your PHP version is outdated. Cryptonite requires PHP >= ' . self::REQUIRED_PHP_VERSION . '. Your version is ' . PHP_VERSION . '.');
    }

    // Works only with OpenSSL version 0.9.6 or greater
    if (OPENSSL_VERSION_NUMBER < self::REQUIRED_OPENSSL_VERSION) {
      throw new EncryptionException('Your OpenSSL version is outdated. Cryptonite requires OpenSSL >= 0.9.6');
    }

    // Prevent heard-bleed exploits (between 1.0.1 and 1.0.1f)
    if (OPENSSL_VERSION_NUMBER >= 0x01000100f && OPENSSL_VERSION_NUMBER <= 0x01000106f) {
      throw new EncryptionException('Your OpenSSL version is between 1.0.1 and 1.0.1f. Update OpenSSL to prevent heard-bleed exploits.');
    }
  }

  /**
   * Hash
   *
   * @param  string Plain string to hash
   *
   * @return binary
   */
  protected function hash($string) {
    return hash($this->hashMethod, $string, true);
  }

  /**
   * Get error messages from OpenSSL
   *
   * @return string
   */
  protected function getErrorString() {
    $errstr = '';
    while ($msg = openssl_error_string())
      $errstr .= $msg . "<br />\n";
    return $errstr;
  }
}
