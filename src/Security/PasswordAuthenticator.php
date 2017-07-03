<?php

declare(strict_types = 1);

namespace AipNg\Security;

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
	 * @throws \AipNg\Security\AccountNotFound
	 * @throws \AipNg\Security\PasswordNotMatch
	 */
	public function authenticate(array $credentials): IIdentity
	{
		[$userName, $password] = $credentials;

		$account = $this->repository->getByUserName($userName);

		if (!$account->verifyPassword($password, $this->hashProvider)) {
			throw new PasswordNotMatch('Invalid password!');
		}

		return $account;
	}

}
