<?php

/**
 * @package Cryptonite
 * @since   2.0.0
 */
namespace Cryptonite;

/**
 * Asymmetric Encryption
 *
 * @package Cryptonite
 */
class AsymmetricEncryption extends Encryption {
  /**
   * Key
   *
   * @var resource
   */
  protected $pKey;

  /**
   * Padding method
   *
   * @var int
   */
  protected $padding = OPENSSL_PKCS1_PADDING;

  /**
   * Config arguments for private key exports
   *
   * @see http://cn2.php.net/manual/de/function.openssl-csr-new.php
   * @var array
   */
  protected $configargs = array(
    'private_key_bits' => 4096,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,

    // Set this to false, to disable private key encryption.
    // Set to true requires a passphrase while decrypting
    'encrypt_key' => true,

    // Some constants are implemented just since PHP 5.4.0:
    //  - OPENSSL_CIPHER_AES_128_CBC = 5
    //  - OPENSSL_CIPHER_AES_192_CBC = 6
    //  - OPENSSL_CIPHER_AES_256_CBC = 7
    // @see http://php.net/manual/en/openssl.ciphers.php
    'encrypt_key_cipher' => 7
  );

  /**
   * Constructor
   *
   * @param array   $configargs Config arguments
   * @param integer $padding    Encryption padding
   *
   * @see http://cn2.php.net/manual/de/function.openssl-csr-new.php
   * @throws EncryptionException
   */
  public function __construct($configargs = array(), $padding = OPENSSL_PKCS1_PADDING) {
    parent::__construct();
    $this->padding = $padding;

    // Merge configurations
    $this->configargs['digest_alg'] = $this->hashMethod;
    $this->configargs = array_merge($this->configargs, $configargs);

    if (!$this->pKey = openssl_pkey_new($this->configargs)) {
      // Fall-back to minimalistic `openssl.cnf`
      $this->configargs['config'] = dirname(__FILE__) . '/openssl.cnf';
    }

    // There is no `openssl.cnf`...
    if (!$this->pKey = openssl_pkey_new($this->configargs))
      throw new EncryptionException("Can't find `openssl.cnf`. Make sure you have a valid `openssl.cnf` installed.");
  }

  /**
   * Encrypt data with public key
   *
   * @param  string $data      Plain data to encrypt
   * @param  string $publicKey Raw key
   *
   * @return binary            Encrypted data
   * @throws EncryptionException
   */
  public function encrypt($data, $publicKey) {
    if (openssl_public_encrypt($data, $encrypted, $publicKey, $this->padding))
      return $encrypted;

    throw new EncryptionException("Something went wrong while encrypting: {$this->getErrorString()}");
  }

  /**
   * Decrypt data with private key
   *
   * @param  string       $data       Raw data to decrypt
   * @param  string       $privateKey Raw key
   *
   * @return string|false             Decrypted data or false on failure
   * @throws EncryptionException
   */
  public function decrypt($data, $privateKey, $passphrase = null) {
    if (is_null($passphrase) && $this->configargs['encrypt_key'])
      throw new EncryptionException("Passphrase missing. Private key is protected with a passphrase.");

    if ($privateKey = openssl_pkey_get_private($privateKey, $passphrase)) {
      if (openssl_private_decrypt($data, $decrypted, $privateKey, $this->padding))
        return $decrypted;

      throw new EncryptionException("Something went wrong while decrypting: {$this->getErrorString()}");
    }

    return false;
  }

  /**
   * Get the private key
   * If `encrypt_key` is set to true, passphrase is required
   *
   * @param  string $passphrase
   *
   * @return string             PEM representation of the key
   * @throws EncryptionException
   */
  public function getPrivateKey($passphrase = null) {
    if (is_null($passphrase) && $this->configargs['encrypt_key'])
      throw new EncryptionException("Passphrase missing. Exported private key have to be encrypted with a passphrase.");

    // Export private key from resource
    if (openssl_pkey_export($this->pKey, $privateKey, $passphrase, $this->configargs))
      return $privateKey;

    throw new EncryptionException("Something went wrong while exporting private key: {$this->getErrorString()}");
  }
  /**
   * Export private key to a file
   * If `encrypt_key` is set to true, passphrase is required
   *
   * @param  string $filename   Name and path to the file
   * @param  string $passphrase
   *
   * @return boolean            true on success
   * @throws EncryptionException
   */
  public function exportPrivateKey($filename, $passphrase = null) {
    if (is_null($passphrase) && $this->configargs['encrypt_key'])
      throw new EncryptionException("Passphrase missing. Exported private key have to be encrypted with a passphrase.");

    // Export private key to a file from resource
    if (openssl_pkey_export_to_file($this->pKey, $filename, $passphrase, $this->configargs))
      return true;

    throw new EncryptionException("Something went wrong while exporting private key: {$this->getErrorString()}");
  }

  /**
   * Get public key
   *
   * @return string PEM representation of the key
   *
   * @throws EncryptionException
   */
  public function getPublicKey() {
    if ($details = openssl_pkey_get_details($this->pKey))
      return $details['key'];

    throw new EncryptionException("Something went wrong while exporting public key: {$this->getErrorString()}");
  }

  /**
   * Export public key to a file
   *
   * @param  string $filename Name and path to the file
   *
   * @return boolean          true on success
   * @throws EncryptionException
   */
  public function exportPublicKey($filename) {
    if (file_put_contents($filename, $this->getPublicKey()) !== false)
      return true;

    throw new EncryptionException("Something went wrong while exporting public key.");
  }

  /**
   * Destructor
   */
  public function __destruct() {
    openssl_pkey_free($this->pKey);
  }
}
