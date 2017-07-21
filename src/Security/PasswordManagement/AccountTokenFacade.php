<?php

declare(strict_types = 1);

namespace AipNg\Security\PasswordManagement;

use AipNg\Security\Account;
use AipNg\Security\AccountFacade;

final class AccountTokenFacade
{

	/** @var \AipNg\Security\PasswordManagement\TokenGenerator */
	private $generator;

	/** @var \AipNg\Security\AccountFacade */
	private $accountFacade;


	public function __construct(TokenGenerator $generator, AccountFacade $accountFacade)
	{
		$this->generator = $generator;
		$this->accountFacade = $accountFacade;
	}


	/**
	 * @param \AipNg\Security\Account $account
	 *
	 * @return \AipNg\Security\PasswordManagement\GeneratedToken
	 *
	 * @throws \AipNg\Security\AccountNotSavedException
	 */
	public function generateTokenForAccount(Account $account): GeneratedToken
	{
		$token = $this->generator->generate();

		$account->setPasswordToken($token);
		$this->accountFacade->save($account);

		return new GeneratedToken($account, $token);
	}

}
