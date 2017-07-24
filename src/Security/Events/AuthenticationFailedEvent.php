<?php

declare(strict_types = 1);

namespace AipNg\Security\Events;

use AipNg\Security\Account;
use Symfony\Component\EventDispatcher\Event;

final class AuthenticationFailedEvent extends Event
{

	/** @var \AipNg\Security\Account */
	private $account;


	public function __construct(Account $account)
	{
		$this->account = $account;
	}


	public function getAccount(): Account
	{
		return $this->account;
	}

}
