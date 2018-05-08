<?php

/**
 * Class Cipher
 */
class Cipher {

  /**
   * Encryption cipher
   *
   * @var    string
   */
  protected $_cipher = 'aes-128';

  /**
   * Cipher mode
   *
   * @var    string
   */
  protected $_mode = 'cbc';

  /**
   * Cipher handle
   *
   * @var    mixed
   */
  protected $_handle;

  /**
   * Encryption key
   *
   * @var    string
   */
  protected $_key;

  /**
   * PHP extension to be used
   *
   * @var    string
   */
  protected $_driver;

  /**
   * List of usable drivers (PHP extensions)
   *
   * @var    array
   */
  protected $_drivers = [];

  /**
   * List of available modes
   *
   * @var    array
   */
  protected $_modes = [
    'mcrypt' => [
      'cbc' => 'cbc',
      'ecb' => 'ecb',
      'ofb' => 'nofb',
      'ofb8' => 'ofb',
      'cfb' => 'ncfb',
      'cfb8' => 'cfb',
      'ctr' => 'ctr',
      'stream' => 'stream'
    ],
    'openssl' => [
      'cbc' => 'cbc',
      'ecb' => 'ecb',
      'ofb' => 'ofb',
      'cfb' => 'cfb',
      'cfb8' => 'cfb8',
      'ctr' => 'ctr',
      'stream' => '',
      'xts' => 'xts'
    ]
  ];

  /**
   * List of supported HMAC algorithms
   *
   * name => digest size pairs
   *
   * @var    array
   */
  protected $_digests = [
    'sha224' => 28,
    'sha256' => 32,
    'sha384' => 48,
    'sha512' => 64
  ];

  /**
   * mbstring.func_overload flag
   *
   * @var    bool
   */
  protected static $func_overload;

  /**
   * Class constructor
   *
   * @param array $params
   */
  public function __construct(array $params = []) {
    $this->_drivers = [
      'mcrypt' => defined('MCRYPT_DEV_URANDOM'),
      'openssl' => extension_loaded('openssl')
    ];

    if (!$this->_drivers['mcrypt'] && !$this->_drivers['openssl']) {

      // Show error message when encryption driver is not available.
      $this->show_error('Unable to find an available encryption driver.');
    }

    isset(self::$func_overload) OR self::$func_overload = (extension_loaded('mbstring') && ini_get('mbstring.func_overload'));
    $this->initialize($params);

    echo 'Encryption Class Initialized';
  }

  /**
   * Initialize
   *
   * @param array $params
   * @return $this
   */
  public function initialize(array $params) {

    if (!empty($params['driver'])) {
      if (isset($this->_drivers[$params['driver']])) {
        if ($this->_drivers[$params['driver']]) {
          $this->_driver = $params['driver'];
        } else {

          // Show error message when driver is not available.
          $this->show_error('Driver ' . $params['driver'] . ' is not available.');
        }
      } else {

        // Show error message when unknown driver is configured.
        $this->show_error('Unknown driver ' . $params['driver'] . ' cannot be configured.');
      }
    }

    if (empty($this->_driver)) {
      $this->_driver = ($this->_drivers['openssl'] === TRUE)
        ? 'openssl'
        : 'mcrypt';

      // Show info message of auto-configured driver.
      echo 'Encryption: Auto-configured driver ' . $this->_driver . '.';
    }

    empty($params['cipher']) && $params['cipher'] = $this->_cipher;
    empty($params['key']) OR $this->_key = $params['key'];

    // Call driver specific initialization method.
    $this->{'_' . $this->_driver . '_initialize'}($params);
    return $this;
  }

  /**
   * Initialize MCrypt
   *
   * @param $params
   */
  protected function _mcrypt_initialize($params) {
    if (!empty($params['cipher'])) {
      $params['cipher'] = strtolower($params['cipher']);
      $this->_cipher_alias($params['cipher']);

      if (!in_array($params['cipher'], mcrypt_list_algorithms(), TRUE)) {

        // Show error message when MCrypt cipher is not available.
        $this->show_error('MCrypt cipher ' . strtoupper($params['cipher']) . ' is not available.');
      } else {
        $this->_cipher = $params['cipher'];
      }
    }

    if (!empty($params['mode'])) {
      $params['mode'] = strtolower($params['mode']);
      if (!isset($this->_modes['mcrypt'][$params['mode']])) {
        $this->show_error('MCrypt mode ' . strtoupper($params['mode']) . ' is not available.');
      } else {
        $this->_mode = $this->_modes['mcrypt'][$params['mode']];
      }
    }

    if (isset($this->_cipher, $this->_mode)) {
      if (is_resource($this->_handle)
        && (strtolower(mcrypt_enc_get_algorithms_name($this->_handle)) !== $this->_cipher
          OR strtolower(mcrypt_enc_get_modes_name($this->_handle)) !== $this->_mode)
      ) {
        mcrypt_module_close($this->_handle);
      }

      if ($this->_handle = mcrypt_module_open($this->_cipher, '', $this->_mode, '')) {
        echo 'Encryption: MCrypt cipher ' . strtoupper($this->_cipher) . ' initialized in ' . strtoupper($this->_mode) . ' mode.';
      } else {

        // Show error message when initialization of MCrypt with cipher is in wrong mode.
        $this->show_error('Unable to initialize MCrypt with cipher ' . strtoupper($this->_cipher) . ' in ' . strtoupper($this->_mode) . ' mode.');
      }
    }
  }

  /**
   * Initialize OpenSSL
   *
   * @param $params
   */
  protected function _openssl_initialize($params) {
    if (!empty($params['cipher'])) {
      $params['cipher'] = strtolower($params['cipher']);
      $this->_cipher_alias($params['cipher']);
      $this->_cipher = $params['cipher'];
    }

    if (!empty($params['mode'])) {
      $params['mode'] = strtolower($params['mode']);
      if (!isset($this->_modes['openssl'][$params['mode']])) {

        // Show error message when OpenSSL mode is not available.
        $this->show_error('OpenSSL mode ' . strtoupper($params['mode']) . ' is not available.');
      } else {
        $this->_mode = $this->_modes['openssl'][$params['mode']];
      }
    }

    if (isset($this->_cipher, $this->_mode)) {

      // This is mostly for the stream mode, which doesn't get suffixed in OpenSSL
      $handle = empty($this->_mode)
        ? $this->_cipher
        : $this->_cipher . '-' . $this->_mode;

      if (!in_array($handle, openssl_get_cipher_methods(), TRUE)) {
        $this->_handle = NULL;

        // Show error message when initialization of OpenSSL with wrong method.
        $this->show_error('Encryption: Unable to initialize OpenSSL with method ' . strtoupper($handle) . '.');
      } else {
        $this->_handle = $handle;
        echo 'Encryption: OpenSSL initialized with method ' . strtoupper($handle) . '.';
      }
    }
  }

  /**
   * Create a random key
   *
   * @param $length
   * @return bool|string
   */
  public function create_key($length) {
    if (function_exists('random_bytes')) {
      try {
        return random_bytes((int)$length);
      } catch (Exception $e) {
        $this->show_error($e->getMessage());
        return FALSE;
      }
    } elseif (defined('MCRYPT_DEV_URANDOM')) {
      return mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
    }

    $is_secure = NULL;
    $key = openssl_random_pseudo_bytes($length, $is_secure);
    return ($is_secure === TRUE)
      ? $key
      : FALSE;
  }

  /**
   * Encrypt
   *
   * @param $data
   * @param array $params
   * @return bool|string
   */
  public function encrypt($data, array $params = NULL) {

    if (($params = $this->_get_params($params)) === FALSE) {
      return FALSE;
    }
    isset($params['key']) OR $params['key'] = $this->hkdf($this->_key, 'sha512', NULL, self::strlen($this->_key), 'encryption');

    if (($data = $this->{'_' . $this->_driver . '_encrypt'}($data, $params)) === FALSE) {
      return FALSE;
    }

    $params['base64'] && $data = base64_encode($data);

    if (isset($params['hmac_digest'])) {
      isset($params['hmac_key']) OR $params['hmac_key'] = $this->hkdf($this->_key, 'sha512', NULL, NULL, 'authentication');
      return hash_hmac($params['hmac_digest'], $data, $params['hmac_key'], !$params['base64']) . $data;
    }

    return $data;
  }

  /**
   * Encrypt via MCrypt
   *
   * @param $data
   * @param $params
   * @return bool|string
   */
  protected function _mcrypt_encrypt($data, $params) {

    if (!is_resource($params['handle'])) {
      return FALSE;
    }

    $iv = (($iv_size = mcrypt_enc_get_iv_size($params['handle'])) > 1)
      ? $this->create_key($iv_size)
      : NULL;

    if (mcrypt_generic_init($params['handle'], $params['key'], $iv) < 0) {
      if ($params['handle'] !== $this->_handle) {
        mcrypt_module_close($params['handle']);
      }

      return FALSE;
    }

    // Use PKCS#7 padding in order to ensure compatibility with OpenSSL
    if (in_array(strtolower(mcrypt_enc_get_modes_name($params['handle'])), ['cbc', 'ecb'], TRUE)) {
      $block_size = mcrypt_enc_get_block_size($params['handle']);
      $pad = $block_size - (self::strlen($data) % $block_size);
      $data .= str_repeat(chr($pad), $pad);
    }

    $data = (mcrypt_enc_get_modes_name($params['handle']) !== 'ECB')
      ? $iv . mcrypt_generic($params['handle'], $data)
      : mcrypt_generic($params['handle'], $data);

    mcrypt_generic_deinit($params['handle']);
    if ($params['handle'] !== $this->_handle) {
      mcrypt_module_close($params['handle']);
    }

    return $data;
  }

  /**
   * Encrypt via OpenSSL
   *
   * @param $data
   * @param $params
   * @return bool|string
   */
  protected function _openssl_encrypt($data, $params) {

    if (empty($params['handle'])) {
      return FALSE;
    }

    $iv = ($iv_size = openssl_cipher_iv_length($params['handle']))
      ? $this->create_key($iv_size)
      : NULL;

    $data = openssl_encrypt(
      $data,
      $params['handle'],
      $params['key'],
      OPENSSL_RAW_DATA,
      $iv
    );

    if ($data === FALSE) {
      return FALSE;
    }

    return $iv . $data;
  }

  /**
   * Decrypt
   *
   * @param $data
   * @param array $params
   * @return bool
   */
  public function decrypt($data, array $params = NULL) {
    if (($params = $this->_get_params($params)) === FALSE) {
      return FALSE;
    }

    if (isset($params['hmac_digest'])) {
      $digest_size = ($params['base64'])
        ? $this->_digests[$params['hmac_digest']] * 2
        : $this->_digests[$params['hmac_digest']];

      if (self::strlen($data) <= $digest_size) {
        return FALSE;
      }

      $hmac_input = self::substr($data, 0, $digest_size);
      $data = self::substr($data, $digest_size);

      isset($params['hmac_key']) OR $params['hmac_key'] = $this->hkdf($this->_key, 'sha512', NULL, NULL, 'authentication');
      $hmac_check = hash_hmac($params['hmac_digest'], $data, $params['hmac_key'], !$params['base64']);

      $diff = 0;
      for ($i = 0; $i < $digest_size; $i++) {
        $diff |= ord($hmac_input[$i]) ^ ord($hmac_check[$i]);
      }

      if ($diff !== 0) {
        return FALSE;
      }
    }

    if ($params['base64']) {
      $data = base64_decode($data);
    }

    isset($params['key']) OR $params['key'] = $this->hkdf($this->_key, 'sha512', NULL, self::strlen($this->_key), 'encryption');

    return $this->{'_' . $this->_driver . '_decrypt'}($data, $params);
  }

  /**
   * Decrypt via MCrypt
   *
   * @param $data
   * @param $params
   * @return bool|string
   */
  protected function _mcrypt_decrypt($data, $params) {
    if (!is_resource($params['handle'])) {
      return FALSE;
    }

    if (($iv_size = mcrypt_enc_get_iv_size($params['handle'])) > 1) {
      if (mcrypt_enc_get_modes_name($params['handle']) !== 'ECB') {
        $iv = self::substr($data, 0, $iv_size);
        $data = self::substr($data, $iv_size);
      } else {
        $iv = str_repeat("\x0", $iv_size);
      }
    } else {
      $iv = NULL;
    }

    if (mcrypt_generic_init($params['handle'], $params['key'], $iv) < 0) {
      if ($params['handle'] !== $this->_handle) {
        mcrypt_module_close($params['handle']);
      }

      return FALSE;
    }

    $data = mdecrypt_generic($params['handle'], $data);

    // Remove PKCS#7 padding, if necessary
    if (in_array(strtolower(mcrypt_enc_get_modes_name($params['handle'])), ['cbc', 'ecb'], TRUE)) {
      $data = self::substr($data, 0, -ord($data[self::strlen($data) - 1]));
    }

    mcrypt_generic_deinit($params['handle']);
    if ($params['handle'] !== $this->_handle) {
      mcrypt_module_close($params['handle']);
    }

    return $data;
  }

  /**
   * Decrypt via OpenSSL
   *
   * @param $data
   * @param $params
   * @return bool|string
   */
  protected function _openssl_decrypt($data, $params) {
    if ($iv_size = openssl_cipher_iv_length($params['handle'])) {
      $iv = self::substr($data, 0, $iv_size);
      $data = self::substr($data, $iv_size);
    } else {
      $iv = NULL;
    }

    return empty($params['handle'])
      ? FALSE
      : openssl_decrypt(
        $data,
        $params['handle'],
        $params['key'],
        OPENSSL_RAW_DATA,
        $iv
      );
  }

  /**
   * Get params
   *
   * @param $params
   * @return array|bool
   */
  protected function _get_params($params) {
    if (empty($params)) {
      return isset($this->_cipher, $this->_mode, $this->_key, $this->_handle)
        ? [
          'handle' => $this->_handle,
          'cipher' => $this->_cipher,
          'mode' => $this->_mode,
          'key' => NULL,
          'base64' => TRUE,
          'hmac_digest' => 'sha512',
          'hmac_key' => NULL
        ]
        : FALSE;
    } elseif (!isset($params['cipher'], $params['mode'], $params['key'])) {
      return FALSE;
    }
    if (isset($params['mode'])) {
      $params['mode'] = strtolower($params['mode']);
      if (!isset($this->_modes[$this->_driver][$params['mode']])) {
        return FALSE;
      }

      $params['mode'] = $this->_modes[$this->_driver][$params['mode']];
    }

    if (isset($params['hmac']) && $params['hmac'] === FALSE) {
      $params['hmac_digest'] = $params['hmac_key'] = NULL;
    } else {
      if (!isset($params['hmac_key'])) {
        return FALSE;
      } elseif (isset($params['hmac_digest'])) {
        $params['hmac_digest'] = strtolower($params['hmac_digest']);
        if (!isset($this->_digests[$params['hmac_digest']])) {
          return FALSE;
        }
      } else {
        $params['hmac_digest'] = 'sha512';
      }
    }

    $params = [
      'handle' => NULL,
      'cipher' => $params['cipher'],
      'mode' => $params['mode'],
      'key' => $params['key'],
      'base64' => isset($params['raw_data']) ? !$params['raw_data'] : FALSE,
      'hmac_digest' => $params['hmac_digest'],
      'hmac_key' => $params['hmac_key']
    ];

    $this->_cipher_alias($params['cipher']);
    $params['handle'] = ($params['cipher'] !== $this->_cipher OR $params['mode'] !== $this->_mode)
      ? $this->{'_' . $this->_driver . '_get_handle'}($params['cipher'], $params['mode'])
      : $this->_handle;

    return $params;
  }

  /**
   * Get MCrypt handle
   *
   * @param $cipher
   * @param $mode
   * @return resource
   */
  protected function _mcrypt_get_handle($cipher, $mode) {
    return mcrypt_module_open($cipher, '', $mode, '');
  }

  /**
   * Get OpenSSL handle
   *
   * @param $cipher
   * @param $mode
   * @return string
   */
  protected function _openssl_get_handle($cipher, $mode) {

    // OpenSSL methods aren't suffixed with '-stream' for this mode.
    return ($mode === 'stream')
      ? $cipher
      : $cipher . '-' . $mode;
  }

  /**
   * Define cipher alias
   *
   * @param $cipher
   */
  protected function _cipher_alias(&$cipher) {
    static $dictionary;

    if (empty($dictionary)) {
      $dictionary = [
        'mcrypt' => [
          'aes-128' => 'rijndael-128',
          'aes-192' => 'rijndael-128',
          'aes-256' => 'rijndael-128',
          'des3-ede3' => 'tripledes',
          'bf' => 'blowfish',
          'cast5' => 'cast-128',
          'rc4' => 'arcfour',
          'rc4-40' => 'arcfour'
        ],
        'openssl' => [
          'rijndael-128' => 'aes-128',
          'tripledes' => 'des-ede3',
          'blowfish' => 'bf',
          'cast-128' => 'cast5',
          'arcfour' => 'rc4-40',
          'rc4' => 'rc4-40'
        ]
      ];
    }

    if (isset($dictionary[$this->_driver][$cipher])) {
      $cipher = $dictionary[$this->_driver][$cipher];
    }
  }

  /**
   * @param $key
   * @param string $digest
   * @param null $salt
   * @param null $length
   * @param string $info
   * @return bool|string
   */
  public function hkdf($key, $digest = 'sha512', $salt = NULL, $length = NULL, $info = '') {
    if (!isset($this->_digests[$digest])) {
      return FALSE;
    }

    if (empty($length) OR !is_int($length)) {
      $length = $this->_digests[$digest];
    } elseif ($length > (255 * $this->_digests[$digest])) {
      return FALSE;
    }

    self::strlen($salt) OR $salt = str_repeat("\0", $this->_digests[$digest]);

    $prk = hash_hmac($digest, $key, $salt, TRUE);
    $key = '';
    for ($key_block = '', $block_index = 1; self::strlen($key) < $length; $block_index++) {
      $key_block = hash_hmac($digest, $key_block . $info . chr($block_index), $prk, TRUE);
      $key .= $key_block;
    }

    return self::substr($key, 0, $length);
  }

  /**
   * @param $key
   * @return mixed|null
   */
  public function __get($key) {

    // Because aliases
    if ($key === 'mode') {
      return array_search($this->_mode, $this->_modes[$this->_driver], TRUE);
    } elseif (in_array($key, ['cipher', 'driver', 'drivers', 'digests'], TRUE)) {
      return $this->{'_' . $key};
    }

    return NULL;
  }

  /**
   * @param $str
   * @return int
   */
  protected static function strlen($str) {
    return (self::$func_overload)
      ? mb_strlen($str, '8bit')
      : strlen($str);
  }

  /**
   * @param $str
   * @param $start
   * @param null $length
   * @return string
   */
  protected static function substr($str, $start, $length = NULL) {
    if (self::$func_overload) {
      return mb_substr($str, $start, $length, '8bit');
    }

    return isset($length)
      ? substr($str, $start, $length)
      : substr($str, $start);
  }

  /**
   * @param $error
   */
  public function show_error($error) {
    echo "Error: " . $error;
  }
}
