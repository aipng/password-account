<?php

declare(strict_types = 1);

namespace AipNg\Security;

use AipNg\Security\Events\AuthenticationFailedEvent;
use Nette\Security\AuthenticationException;
use Nette\Security\IAuthenticator;
use Nette\Security\IIdentity;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

final class PasswordAuthenticator implements
	\Nette\Security\IAuthenticator
{

	/** @var \AipNg\Security\AccountRepository */
	private $repository;

	/** @var \AipNg\Security\PasswordHashProvider */
	private $hashProvider;

	/** @var \Symfony\Component\EventDispatcher\EventDispatcherInterface */
	private $eventDispatcher;


	public function __construct(
		AccountRepository $repository,
		PasswordHashProvider $hashProvider,
		EventDispatcherInterface $eventDispatcher
	)
	{
		$this->repository = $repository;
		$this->hashProvider = $hashProvider;
		$this->eventDispatcher = $eventDispatcher;
	}


	/**
	 * @param string[] $credentials
	 *
	 * @return \Nette\Security\IIdentity
	 *
	 * @throws \Nette\Security\AuthenticationException
	 *
	 * @throws \AipNg\Security\AccountNotFoundException
	 * @throws \AipNg\Security\PasswordNotMatchException
	 */
	public function authenticate(array $credentials): IIdentity
	{
		[$userName, $password] = $credentials;

		try {
			$account = $this->repository->getByUserName($userName);
		} catch (AccountNotFoundException $e) {
			throw new AuthenticationException('User account not found.', IAuthenticator::IDENTITY_NOT_FOUND, $e);
		} catch (\Throwable $e) {
			throw new AuthenticationException('Authentication failed.', IAuthenticator::FAILURE, $e);
		}

		if (!$account->verifyPassword($password, $this->hashProvider)) {
			$this->dispatchAuthenticationFailedEvent($account);

			throw new AuthenticationException('Invalid password.', IAuthenticator::INVALID_CREDENTIAL);
		}

		return $account;
	}


	private function dispatchAuthenticationFailedEvent(Account $account): void
	{
		$event = new AuthenticationFailedEvent($account);

		$this->eventDispatcher->dispatch(AuthenticationFailedEvent::class, $event);
	}

}
