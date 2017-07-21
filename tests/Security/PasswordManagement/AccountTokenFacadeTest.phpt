<?php

declare(strict_types = 1);

namespace AipNg\Tests\Security\PasswordManagement;

require __DIR__ . '/../../bootstrap.php';

use AipNg\Security\Account;
use AipNg\Security\AccountFacade;
use AipNg\Security\AccountNotSavedException;
use AipNg\Security\PasswordManagement\AccountTokenFacade;
use AipNg\Security\PasswordManagement\SecureToken;
use AipNg\Security\PasswordManagement\TokenGenerator;
use Mockery\MockInterface;
use Tester\Assert;
use Tester\TestCase;

final class AccountTokenFacadeTest extends TestCase
{

	public function testGenerateToken(): void
	{
		$token = 'secure-token';

		$secureToken = new SecureToken($token, new \DateTimeImmutable);

		$account = \Mockery::mock(Account::class);
		$account
			->shouldReceive('setPasswordToken')
			->once()
			->with($secureToken);

		$accountFacade = \Mockery::mock(AccountFacade::class);
		$accountFacade
			->shouldReceive('save')
			->once()
			->with($account);

		$facade = new AccountTokenFacade($this->mockGenerator($secureToken), $accountFacade);

		$generatedToken = $facade->generateTokenForAccount($account);

		Assert::same($secureToken, $generatedToken->getSecureToken());
		Assert::same($account, $generatedToken->getAccount());
	}


	public function testGenerateTokenThrowsExceptionOnSaveError(): void
	{
		$token = 'secure-token';

		$secureToken = new SecureToken($token, new \DateTimeImmutable);

		$account = \Mockery::mock(Account::class);
		$account
			->shouldReceive('setPasswordToken')
			->once()
			->with($secureToken);

		$accountFacade = \Mockery::mock(AccountFacade::class);
		$accountFacade
			->shouldReceive('save')
			->once()
			->with($account)
			->andThrow(AccountNotSavedException::class);

		$facade = new AccountTokenFacade($this->mockGenerator($secureToken), $accountFacade);

		Assert::exception(function () use ($facade, $account) {
			$facade->generateTokenForAccount($account);
		}, AccountNotSavedException::class);
	}


	private function mockGenerator(SecureToken $token): MockInterface
	{
		$mock = \Mockery::mock(TokenGenerator::class);
		$mock
			->shouldReceive('generate')
			->andReturn($token);

		return $mock;
	}


	protected function tearDown(): void
	{
		parent::tearDown();
		\Mockery::close();
	}

}


(new AccountTokenFacadeTest)->run();
