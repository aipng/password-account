<?php

declare(strict_types = 1);

namespace AipNg\Tests\Security\PasswordManagement;

require __DIR__ . '/../../bootstrap.php';

use AipNg\Security\Account;
use AipNg\Security\AccountFacade;
use AipNg\Security\AccountNotFound;
use AipNg\Security\AccountNotSaved;
use AipNg\Security\AccountRepository;
use AipNg\Security\PasswordHashProvider;
use AipNg\Security\PasswordManagement\PasswordFacade;
use AipNg\Security\PasswordNotMatch;
use AipNg\Security\TokenExpired;
use AipNg\Security\TokenNotMatch;
use Mockery\MockInterface;
use Tester\Assert;
use Tester\TestCase;

final class PasswordFacadeTest extends TestCase
{

	public function testChangePassword(): void
	{
		$userName = 'user-name';
		$currentPassword = 'current-password';
		$newPassword = 'new-password';

		$hashProvider = \Mockery::mock(PasswordHashProvider::class);

		$account = \Mockery::mock(Account::class);
		$account
			->shouldReceive('changePassword')
			->once()
			->with($currentPassword, $newPassword, $hashProvider);

		$facade = new PasswordFacade(
			$this->mockRepositoryGetByUserName($userName, $account),
			$this->mockAccountFacade(),
			$hashProvider
		);

		$facade->changePassword($userName, $currentPassword, $newPassword);

		Assert::$counter++;
	}


	public function testChangePasswordThrowsExceptionOnWrongAccount(): void
	{
		$userName = 'user-name';

		$repository = \Mockery::mock(AccountRepository::class);
		$repository
			->shouldReceive('getByUserName')
			->once()
			->with($userName)
			->andThrow(AccountNotFound::class);

		$facade = new PasswordFacade(
			$repository,
			$this->mockAccountFacade(),
			\Mockery::mock(PasswordHashProvider::class)
		);

		Assert::exception(function () use ($facade, $userName) {
			$facade->changePassword($userName, 'current-password', 'new-password');
		}, AccountNotFound::class);
	}


	public function testChangePasswordThrowsExceptionOnInvalidPassword(): void
	{
		$userName = 'user-name';
		$currentPassword = 'current-password';
		$newPassword = 'new-password';

		$hashProvider = \Mockery::mock(PasswordHashProvider::class);

		$account = \Mockery::mock(Account::class);
		$account
			->shouldReceive('changePassword')
			->once()
			->with($currentPassword, $newPassword, $hashProvider)
			->andThrow(PasswordNotMatch::class);

		$facade = new PasswordFacade(
			$this->mockRepositoryGetByUserName($userName, $account),
			$this->mockAccountFacade(),
			$hashProvider
		);

		Assert::exception(function () use ($facade, $userName, $currentPassword, $newPassword) {
			$facade->changePassword($userName, $currentPassword, $newPassword);
		}, PasswordNotMatch::class);
	}


	public function testChangePasswordThrowsExceptionOnSaveError(): void
	{
		$userName = 'user-name';
		$currentPassword = 'current-password';
		$newPassword = 'new-password';

		$account = \Mockery::mock(Account::class);
		$account
			->shouldReceive('changePassword')
			->once();

		$accountFacade = \Mockery::mock(AccountFacade::class);
		$accountFacade
			->shouldReceive('save')
			->andThrow(AccountNotSaved::class);

		$facade = new PasswordFacade(
			$this->mockRepositoryGetByUserName($userName, $account),
			$accountFacade,
			\Mockery::mock(PasswordHashProvider::class)
		);

		Assert::exception(function () use ($facade, $userName, $currentPassword, $newPassword) {
			$facade->changePassword($userName, $currentPassword, $newPassword);
		}, AccountNotSaved::class);
	}


	public function testChangePasswordWithToken(): void
	{
		$token = 'some-secret-token';
		$newPassword = 'new-password';

		$hashProvider = \Mockery::mock(PasswordHashProvider::class);

		$account = \Mockery::mock(Account::class);
		$account
			->shouldReceive('changePasswordWithToken')
			->once()
			->with($token, $newPassword, $hashProvider);

		$facade = new PasswordFacade(
			$this->mockRepositoryGetBySecureToken($token, $account),
			$this->mockAccountFacade(),
			$hashProvider
		);

		$facade->changePasswordWithToken($token, $newPassword);

		Assert::$counter++;
	}


	public function testChangePasswordWithTokenThrowsExceptionOnWrongAccount(): void
	{
		$token = 'user-name';

		$repository = \Mockery::mock(AccountRepository::class);
		$repository
			->shouldReceive('getBySecureToken')
			->once()
			->with($token)
			->andThrow(AccountNotFound::class);

		$facade = new PasswordFacade(
			$repository,
			$this->mockAccountFacade(),
			\Mockery::mock(PasswordHashProvider::class)
		);

		Assert::exception(function () use ($facade, $token) {
			$facade->changePasswordWithToken($token, 'new-password');
		}, AccountNotFound::class);
	}


	public function testChangePasswordWithTokenThrowsExceptionOnInvalidToken(): void
	{
		$token = 'some-secret-token';
		$newPassword = 'new-password';

		$hashProvider = \Mockery::mock(PasswordHashProvider::class);

		$account = \Mockery::mock(Account::class);
		$account
			->shouldReceive('changePasswordWithToken')
			->once()
			->with($token, $newPassword, $hashProvider)
			->andThrow(TokenNotMatch::class);

		$facade = new PasswordFacade(
			$this->mockRepositoryGetBySecureToken($token, $account),
			$this->mockAccountFacade(),
			$hashProvider
		);

		Assert::exception(function () use ($facade, $token, $newPassword) {
			$facade->changePasswordWithToken($token, $newPassword);
		}, TokenNotMatch::class);
	}


	public function testChangePasswordWithTokenThrowsExceptionOnExpiredToken(): void
	{
		$token = 'some-secret-token';
		$newPassword = 'new-password';

		$hashProvider = \Mockery::mock(PasswordHashProvider::class);

		$account = \Mockery::mock(Account::class);
		$account
			->shouldReceive('changePasswordWithToken')
			->once()
			->with($token, $newPassword, $hashProvider)
			->andThrow(TokenExpired::class);

		$facade = new PasswordFacade(
			$this->mockRepositoryGetBySecureToken($token, $account),
			$this->mockAccountFacade(),
			$hashProvider
		);

		Assert::exception(function () use ($facade, $token, $newPassword) {
			$facade->changePasswordWithToken($token, $newPassword);
		}, TokenExpired::class);
	}


	public function testChangePasswordWithTokenThrowsExceptionOnSaveError(): void
	{
		$token = 'some-secret-token';
		$newPassword = 'new-password';

		$hashProvider = \Mockery::mock(PasswordHashProvider::class);

		$account = \Mockery::mock(Account::class);
		$account
			->shouldReceive('changePasswordWithToken')
			->once()
			->with($token, $newPassword, $hashProvider);

		$accountFacade = \Mockery::mock(AccountFacade::class);
		$accountFacade
			->shouldReceive('save')
			->andThrow(AccountNotSaved::class);

		$facade = new PasswordFacade(
			$this->mockRepositoryGetBySecureToken($token, $account),
			$accountFacade,
			$hashProvider
		);

		Assert::exception(function () use ($facade, $token, $newPassword) {
			$facade->changePasswordWithToken($token, $newPassword);
		}, AccountNotSaved::class);
	}


	private function mockAccountFacade(): MockInterface
	{
		$mock = \Mockery::mock(AccountFacade::class);
		$mock->shouldReceive('save');

		return $mock;
	}


	private function mockRepositoryGetByUserName(string $userName, Account $account): MockInterface
	{
		$mock = \Mockery::mock(AccountRepository::class);
		$mock
			->shouldReceive('getByUserName')
			->once()
			->with($userName)
			->andReturn($account);

		return $mock;
	}


	private function mockRepositoryGetBySecureToken(string $token, Account $account): MockInterface
	{
		$mock = \Mockery::mock(AccountRepository::class);
		$mock
			->shouldReceive('getBySecureToken')
			->once()
			->with($token)
			->andReturn($account);

		return $mock;
	}


	protected function tearDown(): void
	{
		parent::tearDown();
		\Mockery::close();
	}

}


(new PasswordFacadeTest)->run();