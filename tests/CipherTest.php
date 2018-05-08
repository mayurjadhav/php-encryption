<?php

use Encryption\Cipher;
use PHPUnit\Framework\TestCase;

abstract class CipherTest extends TestCase  {

  public function encrypt_cipher() {

    $cipher = new Cipher();

    $params = [
      'driver' => 'openssl',
      'cipher' => 'aes-128',
      'mode' => 'cbc',
      'key' => 'key_string',
      'base64' => TRUE,
      'hmac_digest' => 'sha512',
      'hmac_key' => 'hmac_key_string'
    ];

    $encrypt = $cipher->encrypt('4989-1212-1212-1212', $params);

    $this->assertArrayHasKey('4989-1212-1212-1212', $cipher->decrypt($encrypt, $params));
  }
}
