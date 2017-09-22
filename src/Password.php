<?php

/**
 * @package Cryptonite
 * @since   2.0.0
 */
namespace Cryptonite;

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
