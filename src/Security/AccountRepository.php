<?php

declare(strict_types = 1);

namespace AipNg\Security;

interface AccountRepository
{

	/**
	 * @param string $userName
	 *
	 * @return \AipNg\Security\Account
	 *
	 * @throws \AipNg\Security\AccountNotFound
	 */
	public function getByUserName(string $userName): Account;


	/**
	 * @param string $token
	 *
	 * @return \AipNg\Security\Account
	 *
	 * @throws \AipNg\Security\AccountNotFound
	 */
	public function getBySecureToken(string $token): Account;

}
