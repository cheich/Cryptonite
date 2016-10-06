# Cryptonite - the hacker's kryptonite

## Features

- Asymmetric encryption
- Symmetric encryption
- Password hashing

## Requirements

- PHP >= 5.3.3
- OpenSSL >= 0.9.6 - Should not between 1.0.1 and 1.0.1f (prevent Heardbleed exploits, see http://heartbleed.com/)
- Place minimalistic `openssl.cnf` file near `Cryptonite.php` as fall-back

## Examples

### Symmetric encryption

#### Encrypt data

```php
try {
  $symmetric = new SymmetricEncryption();
  $encrypted = $symmetric->encrypt('String to encrypt', 'MyPassphrase');
  $iv        = $symmetric->getInitVector();
} catch (EncryptionException $e) {
  echo "Something went wrong...";
}
```

#### Decrypt data

```php
try {
  $symmetric = new SymmetricEncryption();
  $encrypted = /* get encrypted data from database */;
  $iv        = /* get iv from database */;

  $decrypted = $symmetric->decrypt($encrypted, 'MyPassphrase', $iv);
} catch (EncryptionException $e) {
  echo "Something went wrong...";
}
```

### Asymetric encryption

#### Generate private/public key pair

```php
try {
  $asymmetric = new AsymmetricEncryption();
  $publicKey  = $asymmetric->getPublicKey(); // or export to a file
  $privateKey = $asymmetric->getPrivateKey('MyPassphrase'); // or export to a file
  $encrypted  = $asymmetric->encrypt('String to encrypt', $publicKey);
} catch (EncryptionException $e) {
  echo "Something went wrong...";
}
```

#### Decrypt with private key

```php
try {
  $asymmetric = new AsymmetricEncryption();
  $privateKey = /* get private key */;
  $encrypted  = /* get encrypted data */;

  $decrypted = $asymmetric->decrypt($encrypted, $privateKey, 'MyPassphrase');
} catch (EncryptionException $e) {
  echo "Something went wrong...";
}
```

### Passwords

#### Hash password

```php
try {
  $password = new Password();
  $hashed   = $password->hash('MyPassphrase');
} catch (EncryptionException $e) {
  echo "Something went wrong...";
}
```

#### Verify password

```php
try {
  $password = new Password();
  $hashed   = /* get hashes password */;

  // Returns true or false
  $password->verify('MyPassphrase', $hashed);
} catch (EncryptionException $e) {
  echo "Something went wrong...";
}
```
