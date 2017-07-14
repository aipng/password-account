<?php

declare(strict_types = 1);

namespace AipNg\Tests\Security\PasswordManagement;

require __DIR__ . '/../../bootstrap.php';

use AipNg\Security\Account;
use AipNg\Security\AccountFacade;
use AipNg\Security\AccountNotFound;
use AipNg\Security\AccountNotSaved;
use AipNg\Security\AccountRepository;
use AipNg\Security\PasswordManagement\SecureToken;
use AipNg\Security\PasswordManagement\TokenFacade;
use AipNg\Security\PasswordManagement\TokenGenerator;
use Mockery\MockInterface;
use Tester\Assert;
use Tester\TestCase;

final class TokenFacadeTest extends TestCase
{

	public function testGenerateNewToken(): void
	{
		$userName = 'user-name';
		$token = 'secure-token';

		$secureToken = new SecureToken($token, new \DateTimeImmutable);

		$account = \Mockery::mock(Account::class);
		$account
			->shouldReceive('setPasswordToken')
			->once()
			->with($secureToken);

		$accountRepository = \Mockery::mock(AccountRepository::class);
		$accountRepository
			->shouldReceive('getByUserName')
			->once()
			->with($userName)
			->andReturn($account);

		$accountFacade = \Mockery::mock(AccountFacade::class);
		$accountFacade
			->shouldReceive('save')
			->once()
			->with($account);

		$facade = new TokenFacade($this->mockGenerator($secureToken), $accountRepository, $accountFacade);

		$generatedToken = $facade->generateNewToken($userName);

		Assert::same($secureToken, $generatedToken->getSecureToken());
		Assert::same($account, $generatedToken->getAccount());
	}


	public function testGenerateNewTokenThrowsExceptionOnWrongAccount(): void
	{
		$userName = 'user-name';
		$secureToken = new SecureToken('secure-token', new \DateTimeImmutable);

		$accountRepository = \Mockery::mock(AccountRepository::class);
		$accountRepository
			->shouldReceive('getByUserName')
			->once()
			->with($userName)
			->andThrow(AccountNotFound::class);

		$accountFacade = \Mockery::mock(AccountFacade::class);

		$facade = new TokenFacade($this->mockGenerator($secureToken), $accountRepository, $accountFacade);

		Assert::exception(function () use ($facade, $userName) {
			$facade->generateNewToken($userName);
		}, AccountNotFound::class);
	}


	public function testGenerateNewTokenThrowsExceptionOnSaveError(): void
	{
		$userName = 'user-name';
		$token = 'secure-token';

		$secureToken = new SecureToken($token, new \DateTimeImmutable);

		$account = \Mockery::mock(Account::class);
		$account
			->shouldReceive('setPasswordToken')
			->once()
			->with($secureToken);

		$accountRepository = \Mockery::mock(AccountRepository::class);
		$accountRepository
			->shouldReceive('getByUserName')
			->once()
			->with($userName)
			->andReturn($account);

		$accountFacade = \Mockery::mock(AccountFacade::class);
		$accountFacade
			->shouldReceive('save')
			->once()
			->with($account)
			->andThrow(AccountNotSaved::class);

		$facade = new TokenFacade($this->mockGenerator($secureToken), $accountRepository, $accountFacade);

		Assert::exception(function () use ($facade, $userName) {
			$facade->generateNewToken($userName);
		}, AccountNotSaved::class);
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


(new TokenFacadeTest)->run();
