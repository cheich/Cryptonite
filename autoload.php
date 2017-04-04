<?php

/**
 * @package Cryptonite
 */
namespace Cryptonite;

/**
 * Class autoloader
 *
 * @param string $class The fully-qualified class name
 *
 * @return void
 */
spl_autoload_register(function ($class) {
  $len = strlen(__NAMESPACE__);

  if (strncmp(__NAMESPACE__, $class, $len) !== 0) {
    return;
  }

  $relative_class = substr($class, $len);
  $file = __DIR__ . str_replace('\\', '/', $relative_class) . '.php';

  if (file_exists($file)) {
    require $file;
  }
});
