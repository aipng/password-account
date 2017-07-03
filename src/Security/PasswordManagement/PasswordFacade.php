<?php

declare(strict_types = 1);

namespace AipNg\Security\PasswordManagement;

use AipNg\Security\AccountFacade;
use AipNg\Security\AccountRepository;
use AipNg\Security\PasswordHashProvider;

final class PasswordFacade
{

	/** @var \AipNg\Security\AccountRepository */
	private $accountRepository;

	/** @var \AipNg\Security\AccountFacade */
	private $accountFacade;

	/** @var \AipNg\Security\PasswordHashProvider */
	private $hashProvider;


	public function __construct(AccountRepository $accountRepository, AccountFacade $accountFacade, PasswordHashProvider $hashProvider)
	{
		$this->accountRepository = $accountRepository;
		$this->accountFacade = $accountFacade;
		$this->hashProvider = $hashProvider;
	}


	/**
	 * @param string $userName
	 * @param string $currentPassword
	 * @param string $newPassword
	 *
	 * @throws \AipNg\Security\AccountNotFound
	 * @throws \AipNg\Security\PasswordNotMatch
	 * @throws \AipNg\Security\AccountNotSaved
	 */
	public function changePassword(string $userName, string $currentPassword, string $newPassword): void
	{
		$account = $this->accountRepository->getByUserName($userName);

		$account->changePassword($currentPassword, $newPassword, $this->hashProvider);

		$this->accountFacade->save($account);
	}


	/**
	 * @param string $token
	 * @param string $newPassword
	 *
	 * @throws \AipNg\Security\AccountNotFound
	 * @throws \AipNg\Security\TokenNotMatch
	 * @throws \AipNg\Security\TokenExpired
	 * @throws \AipNg\Security\AccountNotSaved
	 */
	public function changePasswordWithToken(string $token, string $newPassword): void
	{
		$account = $this->accountRepository->getBySecureToken($token);

		$account->changePasswordWithToken($token, $newPassword, $this->hashProvider);

		$this->accountFacade->save($account);
	}

}
