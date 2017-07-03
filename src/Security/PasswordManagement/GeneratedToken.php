<?php

declare(strict_types = 1);

namespace AipNg\Security\PasswordManagement;

use AipNg\Security\Account;

final class GeneratedToken
{

	/** @var \AipNg\Security\Account */
	private $account;

	/** @var \AipNg\Security\PasswordManagement\SecureToken */
	private $secureToken;


	public function __construct(Account $account, SecureToken $secureToken)
	{
		$this->account = $account;
		$this->secureToken = $secureToken;
	}


	public function getAccount(): Account
	{
		return $this->account;
	}


	public function getSecureToken(): SecureToken
	{
		return $this->secureToken;
	}

}
