<?php
declare(strict_types=1);

// Composer's autoloader covers the Kaitai runtime and src/. The generated files
// hold several classes each (one namespace block per nested type), so they're
// loaded here instead of through an autoloader.
require dirname(__DIR__) . '/vendor/autoload.php';

$generated = dirname(__DIR__) . '/generated';
$files = glob($generated . '/*.php') ?: [];
if ($files === []) {
    fwrite(STDERR, "no generated PHP in $generated; run: python scripts/compile.py --target php\n");
    exit(1);
}
foreach ($files as $file) {
    require_once $file;
}
