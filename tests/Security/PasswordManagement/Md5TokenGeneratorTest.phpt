<?php

declare(strict_types = 1);

namespace AipNg\Tests\Security\PasswordManagement;

require __DIR__ . '/../../bootstrap.php';

use AipNg\DateTimeProvider\DateTimeProvider;
use AipNg\Security\PasswordManagement\Md5TokenGenerator;
use Tester\Assert;
use Tester\TestCase;

final class Md5TokenGeneratorTest extends TestCase
{

	public function testGeneratedSecureTokenExpiresInOneHourByDefault(): void
	{
		$date = new \DateTimeImmutable;

		$dateTimeProvider = \Mockery::mock(DateTimeProvider::class);
		$dateTimeProvider
			->shouldReceive('getDateTime')
			->once()
			->andReturn($date);

		$token = (new Md5TokenGenerator($dateTimeProvider))
			->generate();

		$expiresInOneHour = $date->add(new \DateInterval('PT60M'));
		Assert::true($expiresInOneHour <= $token->getValidUntil());

		$expiresInOneHour = $date->add(new \DateInterval('PT61M'));
		Assert::false($expiresInOneHour <= $token->getValidUntil());
	}


	public function testChangeDefaultExpirationPeriod(): void
	{
		$date = new \DateTimeImmutable;

		$dateTimeProvider = \Mockery::mock(DateTimeProvider::class);
		$dateTimeProvider
			->shouldReceive('getDateTime')
			->once()
			->andReturn($date);

		$token = (new Md5TokenGenerator($dateTimeProvider))
			->setTokenExpirationPeriod(new \DateInterval('PT10M'))
			->generate();

		$expireInFiveMinutes = $date->add(new \DateInterval('PT5M'));
		$expireInTwentyMinutes = $date->add(new \DateInterval('PT20M'));

		Assert::true($expireInFiveMinutes <= $token->getValidUntil());
		Assert::true($expireInTwentyMinutes >= $token->getValidUntil());
	}

}


run(new Md5TokenGeneratorTest);
