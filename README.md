# Encryption:

Object-Oriented PHP application for encrypting and decrypting using MCrypt and OpenSSL.

The idea is that you create an array representing certain encryption settings. Then you give it strings to encrypt or decrypt.


# Encryption Using OpenSSL:

```php
<?php

// Configure a set of params to reuse throughout your application:
$params = [
  'driver' => 'openssl',
  'cipher' => 'aes-128',
  'mode' => 'cbc',
  'key' => 'key_string',
  'base64' => TRUE,
  'hmac_digest' => 'sha512',
  'hmac_key' => 'hmac_key_string'
];

// Create an object of Cipher class.
$cipher = new Cipher();

// Encrypting a CreditCard number.
echo $cipher->encrypt('4989-1212-1212-1212', $params);

// "���U�CW>�E�[���=�3������'�N���1ET��ï��z���}CP{�@D"-�R��Ԅ���2WӁ���".<�aE�;�K.-�Ma��e�wC쑁m�R�Q"
// Note: Encrypted strings will be different every time because iv is stored with the output.

echo $cipher->decrypt($encrypted, $params);

// 4989-1212-1212-1212
```

# Encryption Using MCrypt:

```php
<?php

// Configure a set of params to reuse throughout your application:
$params = [
  'driver' => 'mcrypt',
  'cipher' => 'aes-128',
  'mode' => 'cbc',
  'key' => 'key_string',
  'base64' => TRUE,
  'hmac_digest' => 'sha512',
  'hmac_key' => 'hmac_key_string'
];

// Create an object of Cipher class.
$cipher = new Cipher();

// Encrypting a CreditCard number.
echo $cipher->encrypt('4989-1212-1212-1212', $params);

// "���U�CW>�E�[���=�3������'�N���1ET��ï��z���}CP{�@D"-�R��Ԅ���2WӁ���".<�aE�;�K.-�Ma��e�wC쑁m�R�Q"
// Note: Encrypted strings will be different every time because iv is stored with the output.

echo $cipher->decrypt($encrypted, $params);

// 4989-1212-1212-1212
