<?php

declare(strict_types = 1);

namespace AipNg\Security;

use Nette\Security\AuthenticationException;
use Nette\Security\IAuthenticator;
use Nette\Security\IIdentity;

final class PasswordAuthenticator implements
	\Nette\Security\IAuthenticator
{

	/** @var \AipNg\Security\AccountRepository */
	private $repository;

	/** @var \AipNg\Security\PasswordHashProvider */
	private $hashProvider;


	public function __construct(AccountRepository $repository, PasswordHashProvider $hashProvider)
	{
		$this->repository = $repository;
		$this->hashProvider = $hashProvider;
	}


	/**
	 * @param string[] $credentials
	 *
	 * @return \Nette\Security\IIdentity
	 *
	 * @throws \Nette\Security\AuthenticationException
	 *
	 * @throws \AipNg\Security\AccountNotFound
	 * @throws \AipNg\Security\PasswordNotMatch
	 */
	public function authenticate(array $credentials): IIdentity
	{
		[$userName, $password] = $credentials;

		try {
			$account = $this->repository->getByUserName($userName);
		} catch (AccountNotFound $e) {
			throw new AuthenticationException('User account not found.', IAuthenticator::IDENTITY_NOT_FOUND, $e);
		} catch (\Throwable $e) {
			throw new AuthenticationException('Authentication failed.', IAuthenticator::FAILURE, $e);
		}

		if (!$account->verifyPassword($password, $this->hashProvider)) {
			throw new AuthenticationException('Invalid password.', IAuthenticator::INVALID_CREDENTIAL);
		}

		return $account;
	}

}
