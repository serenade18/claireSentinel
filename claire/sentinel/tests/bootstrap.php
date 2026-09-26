<?php

// Works from packages/claire/sentinel (source) and vendor/claire/sentinel (installed copy):
// walk up to the Laravel app root, load its autoloader, then map the test namespace here.
$root = __DIR__;
while (! (is_file($root . '/artisan') && is_file($root . '/vendor/autoload.php'))) {
    if (dirname($root) === $root) {
        fwrite(STDERR, "Sentinel tests must run inside a Laravel app.\n");
        exit(1);
    }
    $root = dirname($root);
}

$loader = require $root . '/vendor/autoload.php';
$loader->addPsr4('Claire\\Sentinel\\Tests\\', __DIR__);
