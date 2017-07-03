<?php

declare(strict_types = 1);

namespace AipNg\Tests\Security;

require_once __DIR__ . '/../bootstrap.php';

use AipNg\Security\DefaultHashProvider;
use Tester\Assert;
use Tester\TestCase;

final class DefaultHashProviderTest extends TestCase
{

	public function testChangePasswordCost(): void
	{
		$hashProvider = new DefaultHashProvider;

		$hashProvider->changePasswordCost(50);

		Assert::same(50, $hashProvider->getPasswordCost());
	}


	public function testVerifyPassword(): void
	{
		$password = 'password';

		//  4 - lowest possible cost for bcrypt, need for speed
		$hashProvider = new DefaultHashProvider(4);
		$hash = $hashProvider->hashPassword($password);

		Assert::true($hashProvider->verifyPassword($password, $hash));
	}


	public function testVerifyPasswordReturnsFalseForInvalidHash(): void
	{
		//  4 - lowest possible cost for bcrypt, need for speed
		$hashProvider = new DefaultHashProvider(4);
		$hash = $hashProvider->hashPassword('password');

		Assert::false($hashProvider->verifyPassword('other-password', $hash));
	}

}


run(new DefaultHashProviderTest);
