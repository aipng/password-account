<?php

declare(strict_types = 1);

namespace AipNg\Security;

interface AccountFacade
{

	/**
	 * @param \AipNg\Security\Account $account
	 *
	 * @throws \AipNg\Security\AccountNotSavedException
	 */
	public function save(Account $account): void;

}
