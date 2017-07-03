<?php

declare(strict_types = 1);

use Nette\Loaders\RobotLoader;
use Tester\Environment;
use Tester\Helpers;
use Tester\TestCase;

require_once __DIR__ . '/../vendor/autoload.php';

define('TMP_DIR', __DIR__ . '/../temp');

Helpers::purge(TMP_DIR);

Environment::setup();
date_default_timezone_set('Europe/Prague');

$loader = new RobotLoader;
$loader
	->setTempDirectory(TMP_DIR)
	->setAutoRefresh()
	->addDirectory(__DIR__)
	->addDirectory(__DIR__ . '/../src');

return $loader->register();

function run(TestCase $case): void
{
	$case->run($_SERVER['argv'][1] ?? NULL);
}
