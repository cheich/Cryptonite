<?php

/**
 * @package Cryptonite
 * @since   2.0.0
 */
namespace Cryptonite;

/**
 * Symmetric Encryption
 *
 * @package Cryptonite
 */
class SymmetricEncryption extends Encryption {
  /**
   * Encryption cipher method
   *
   * @see http://php.net/manual/de/function.openssl-get-cipher-methods.php
   * @var string
   */
  protected $cipherMethod = 'aes-256-cfb';

  /**
   * Last used IV
   *
   * @var string
   */
  protected $initVector;

  /**
   * Constructor
   */
  public function __construct() {
    parent::__construct();
  }

  /**
   * Encrypt data
   *
   * @param  string $data The data to encrypt
   * @param  string $key  Plain encryption key
   *
   * @return binary       Raw encrypted data
   * @throws EncryptionException
   */
  public function encrypt($data, $key) {
    // The 4th parameter is `OPENSSL_RAW_DATA` as integer, the constant was included with PHP 5.4
    if ($encrypted = openssl_encrypt($data, $this->cipherMethod, $this->hash($key), 1, $this->newInitVector()))
      return $encrypted;

    throw new EncryptionException("Something went wrong while encrypting: {$this->getErrorString()}");
  }

  /**
   * Decrypt data
   *
   * @param  binary $data       Raw data to decrypt
   * @param  string $key        Plain encryption key
   * @param  binary $initVector Raw IV
   *
   * @return string             Decrypted data
   * @throws EncryptionException
   */
  public function decrypt($data, $key, $initVector) {
    // The 4th parameter is `OPENSSL_RAW_DATA` as integer, the constant was included with PHP 5.4
    if ($decrypted = openssl_decrypt($data, $this->cipherMethod, $this->hash($key), 1, $initVector))
      return $decrypted;

    throw new EncryptionException("Something went wrong while decrypting: {$this->getErrorString()}");
  }

  /**
   * Get last IV
   *
   * @return binary
   */
  public function getInitVector() {
    return $this->initVector;
  }

  /**
   * Generate a new initialization vector
   *
   * @return binary
   * @throws EncryptionException
   */
  protected function newInitVector() {
    // `openssl_random_pseudo_bytes` generates a new random iv
    // `openssl_cipher_iv_length` gets the required iv length
    $initVector = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cipherMethod), $crypto_strong);

    if ($crypto_strong)
      return $this->initVector = $initVector;

    throw new EncryptionException("No cryptographically strong algorithm used for IV generation. Verify that your encryption method is valid.");
  }
}
