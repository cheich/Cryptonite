<?php

/**
 * Cryptonite - the hacker's kryptonite
 *
 * Features:
 *  - Asymmetric encryption
 *  - Symmetric encryption
 *  - Password hashing
 *
 * Requirements:
 *  - PHP >= 5.3.3
 *  - OpenSSL >= 0.9.6 - Should not between 1.0.1 and 1.0.1f (prevent Heardbleed exploits, see http://heartbleed.com/)
 *
 * Without any warranty! If you see any issues or have a suggestion for improvement, please contact me!
 *
 * @version 2.0.0
 * @author  Christoph Heich <mail@christophheich.de>
 */

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

/**
 * Password
 *
 * @package Cryptonite
 */
class Password {
  /**
   * 2^n cost factor
   * The higher the longer it takes
   *
   * @var int
   */
  protected $costFactor;

  /**
   * Constructor
   *
   * @param int $costFactor 2^n cost factor
   */
  public function __construct($costFactor = 12) {
    $this->costFactor = $costFactor;
  }

  /**
   * Hash a password
   *
   * @param  string $plain Plain password to hash
   *
   * @return string        Hashed value with cost, salt and algorithm
   */
  public function hash($plain) {
    // Since PHP 5.5 we can use `password_hash`
    if (function_exists('password_hash')) {
      return password_hash($plain, PASSWORD_BCRYPT, ['cost' => $this->costFactor]);
    } else {
      $random = openssl_random_pseudo_bytes(18);

      $salt = sprintf('$2y$%02d$%s',
        $this->costFactor,
        substr(strtr(base64_encode($random), '+', '.'), 0, 22)
      );

      return crypt($plain, $salt);
    }
  }

  /**
   * Verify a hashed password
   *
   * @param string $plain Plain password to compare
   * @param string $hash  Hashed password (returned from Cryptonite::hash_password())
   *
   * @return bool
   */
  public function verify($plain, $hash) {
    // Since PHP 5.5 we can use `password_verify`
    if (function_exists('password_verify')) {
      return password_verify($plain, $hash);
    } else {
      $hashRaw = crypt($plain, $hash);
      $hashRawLen = strlen($hashRaw);

      if (strlen($hash) != $hashRawLen)
        return false;

      for ($i = 0, $diff = 0; $i != $hashRawLen; ++$i)
        $diff |= ord($hashRaw[$i]) ^ ord($hash[$i]);

      return !$diff;
    }
  }
}

/**
 * Encryption Exception
 *
 * @package Cryptonite
 */
class EncryptionException extends \Exception {}
