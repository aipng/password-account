<?php

declare(strict_types = 1);

namespace AipNg\Security\PasswordManagement;

use AipNg\Security\Account;
use AipNg\Security\AccountFacade;
use AipNg\Security\Events\AccountTokenGeneratedEvent;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

final class AccountTokenFacade
{

	/** @var \AipNg\Security\PasswordManagement\TokenGenerator */
	private $generator;

	/** @var \AipNg\Security\AccountFacade */
	private $accountFacade;

	/** @var \Symfony\Component\EventDispatcher\EventDispatcherInterface */
	private $eventDispatcher;


	public function __construct(TokenGenerator $generator, AccountFacade $accountFacade, EventDispatcherInterface $eventDispatcher)
	{
		$this->generator = $generator;
		$this->accountFacade = $accountFacade;
		$this->eventDispatcher = $eventDispatcher;
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

		$generatedToken = new GeneratedToken($account, $token);

		$this->dispatchEvent($generatedToken);

		return $generatedToken;
	}


	private function dispatchEvent(GeneratedToken $token): void
	{
		$this->eventDispatcher->dispatch(AccountTokenGeneratedEvent::class, new AccountTokenGeneratedEvent($token));
	}

}
