<?php

declare(strict_types = 1);

namespace AipNg\Security\PasswordManagement;

use AipNg\Security\Account;
use AipNg\Security\AccountFacade;
use AipNg\Security\AccountRepository;
use AipNg\Security\Events\PasswordChangedEvent;
use AipNg\Security\PasswordHashProvider;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

final class PasswordFacade
{

	/** @var \AipNg\Security\AccountRepository */
	private $accountRepository;

	/** @var \AipNg\Security\AccountFacade */
	private $accountFacade;

	/** @var \AipNg\Security\PasswordHashProvider */
	private $hashProvider;

	/** @var \Symfony\Component\EventDispatcher\EventDispatcherInterface */
	private $eventDispatcher;


	public function __construct(
		AccountRepository $accountRepository,
		AccountFacade $accountFacade,
		PasswordHashProvider $hashProvider,
		EventDispatcherInterface $eventDispatcher
	)
	{
		$this->accountRepository = $accountRepository;
		$this->accountFacade = $accountFacade;
		$this->hashProvider = $hashProvider;
		$this->eventDispatcher = $eventDispatcher;
	}


	/**
	 * @param string $userName
	 * @param string $currentPassword
	 * @param string $newPassword
	 *
	 * @throws \AipNg\Security\AccountNotFoundException
	 * @throws \AipNg\Security\PasswordNotMatchException
	 * @throws \AipNg\Security\AccountNotSavedException
	 */
	public function changePassword(string $userName, string $currentPassword, string $newPassword): void
	{
		$account = $this->accountRepository->getByUserName($userName);

		$account->changePassword($currentPassword, $newPassword, $this->hashProvider);

		$this->accountFacade->save($account);

		$this->dispatchPasswordChangedEvent($account);
	}


	/**
	 * @param string $token
	 * @param string $newPassword
	 *
	 * @throws \AipNg\Security\AccountNotFoundException
	 * @throws \AipNg\Security\TokenNotMatchException
	 * @throws \AipNg\Security\TokenExpiredException
	 * @throws \AipNg\Security\AccountNotSavedException
	 */
	public function changePasswordWithToken(string $token, string $newPassword): void
	{
		$account = $this->accountRepository->getBySecureToken($token);

		$account->changePasswordWithToken($token, $newPassword, $this->hashProvider);

		$this->accountFacade->save($account);

		$this->dispatchPasswordChangedEvent($account);
	}


	private function dispatchPasswordChangedEvent(Account $account): void
	{
		$event = new PasswordChangedEvent($account);

		$this->eventDispatcher->dispatch(PasswordChangedEvent::class, $event);
	}

}
