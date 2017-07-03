<?php

declare(strict_types = 1);

namespace AipNg\Security\PasswordManagement;

use AipNg\Security\AccountFacade;
use AipNg\Security\AccountRepository;

final class TokenFacade
{

	/** @var \AipNg\Security\PasswordManagement\TokenGenerator */
	private $generator;

	/** @var \AipNg\Security\AccountRepository */
	private $accountRepository;

	/** @var \AipNg\Security\AccountFacade */
	private $accountFacade;


	public function __construct(TokenGenerator $generator, AccountRepository $accountRepository, AccountFacade $accountFacade)
	{
		$this->generator = $generator;
		$this->accountRepository = $accountRepository;
		$this->accountFacade = $accountFacade;
	}


	/**
	 * @param string $userName
	 *
	 * @return \AipNg\Security\PasswordManagement\GeneratedToken
	 *
	 * @throws \AipNg\Security\AccountNotFound
	 * @throws \AipNg\Security\AccountNotSaved
	 */
	public function generateNewToken(string $userName): GeneratedToken
	{
		$account = $this->accountRepository->getByUserName($userName);
		$token = $this->generator->generate();

		$account->setPasswordToken($token);
		$this->accountFacade->save($account);

		return new GeneratedToken($account, $token);
	}

}
