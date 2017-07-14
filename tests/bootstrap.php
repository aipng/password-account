<?php

declare(strict_types = 1);

use Nette\Loaders\RobotLoader;
use Tester\Environment;

require_once __DIR__ . '/../vendor/autoload.php';

define('TMP_DIR', __DIR__ . '/../temp');

Environment::setup();
date_default_timezone_set('Europe/Prague');

$loader = new RobotLoader;
$loader
	->setTempDirectory(TMP_DIR)
	->setAutoRefresh()
	->addDirectory(__DIR__)
	->addDirectory(__DIR__ . '/../src');

return $loader->register();
