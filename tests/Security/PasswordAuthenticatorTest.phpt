<?php

declare(strict_types = 1);

namespace AipNg\Tests\Security;

require __DIR__ . '/../bootstrap.php';

use AipNg\Security\Account;
use AipNg\Security\AccountNotFoundException;
use AipNg\Security\AccountRepository;
use AipNg\Security\PasswordAuthenticator;
use AipNg\Security\PasswordHashProvider;
use Nette\Security\AuthenticationException;
use Nette\Security\IAuthenticator;
use Tester\Assert;
use Tester\TestCase;

class PasswordAuthenticatorTest extends TestCase
{

	private const USER_NAME = 'user-name';
	private const PASSWORD = 'password';


	public function testAuthenticate(): void
	{
		$hashProvider = \Mockery::mock(PasswordHashProvider::class);

		$account = \Mockery::mock(Account::class);
		$account
			->shouldReceive('verifyPassword')
			->once()
			->with(self::PASSWORD, $hashProvider)
			->andReturn(TRUE);

		$repository = \Mockery::mock(AccountRepository::class);
		$repository
			->shouldReceive('getByUserName')
			->once()
			->with(self::USER_NAME)
			->andReturn($account);

		$authenticator = new PasswordAuthenticator($repository, $hashProvider);

		Assert::same($account, $authenticator->authenticate([self::USER_NAME, self::PASSWORD]));
	}


	public function testThrowsExceptionOnInvalidUser(): void
	{
		$hashProvider = \Mockery::mock(PasswordHashProvider::class);

		$repository = \Mockery::mock(AccountRepository::class);
		$repository
			->shouldReceive('getByUserName')
			->once()
			->andThrow(AccountNotFoundException::class);

		$authenticator = new PasswordAuthenticator($repository, $hashProvider);

		$e = Assert::exception(function () use ($authenticator) {
			$authenticator->authenticate([self::USER_NAME, self::PASSWORD]);
		}, AuthenticationException::class);

		Assert::same(IAuthenticator::IDENTITY_NOT_FOUND, $e->getCode());
	}


	public function testThrowsExceptionOnInvalidPassword(): void
	{
		$hashProvider = \Mockery::mock(PasswordHashProvider::class);

		$account = \Mockery::mock(Account::class);
		$account
			->shouldReceive('verifyPassword')
			->once()
			->with(self::PASSWORD, $hashProvider)
			->andReturn(FALSE);

		$repository = \Mockery::mock(AccountRepository::class);
		$repository
			->shouldReceive('getByUserName')
			->once()
			->with(self::USER_NAME)
			->andReturn($account);

		$authenticator = new PasswordAuthenticator($repository, $hashProvider);

		$e = Assert::exception(function () use ($authenticator) {
			$authenticator->authenticate([self::USER_NAME, self::PASSWORD]);
		}, AuthenticationException::class);

		Assert::same(IAuthenticator::INVALID_CREDENTIAL, $e->getCode());
	}


	public function testThrowExceptionOnError(): void
	{
		$hashProvider = \Mockery::mock(PasswordHashProvider::class);
		$databaseException = new \Exception;

		$repository = \Mockery::mock(AccountRepository::class);
		$repository
			->shouldReceive('getByUserName')
			->once()
			->with(self::USER_NAME)
			->andThrow($databaseException);

		$authenticator = new PasswordAuthenticator($repository, $hashProvider);

		$e = Assert::exception(function () use ($authenticator) {
			$authenticator->authenticate([self::USER_NAME, self::PASSWORD]);
		}, AuthenticationException::class);

		Assert::same(IAuthenticator::FAILURE, $e->getCode());
		Assert::same($databaseException, $e->getPrevious());
	}


	protected function tearDown(): void
	{
		parent::tearDown();
		\Mockery::close();
	}

}


(new PasswordAuthenticatorTest)->run();
