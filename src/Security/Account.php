<?php

declare(strict_types = 1);

namespace AipNg\Security;

use AipNg\Security\PasswordManagement\SecureToken;
use Nette\Security\IIdentity;

interface Account extends IIdentity
{

	/**
	 * @param string $currentPassword
	 * @param string $newPasswordHash
	 * @param \AipNg\Security\PasswordHashProvider $hashProvider
	 *
	 * @throws \AipNg\Security\PasswordNotMatch
	 */
	public function changePassword(string $currentPassword, string $newPasswordHash, PasswordHashProvider $hashProvider): void;


	/**
	 * @param string $token
	 * @param string $newPassword
	 * @param \AipNg\Security\PasswordHashProvider $hashProvider
	 *
	 * @throws \AipNg\Security\TokenNotMatch
	 * @throws \AipNg\Security\TokenExpired
	 */
	public function changePasswordWithToken(string $token, string $newPassword, PasswordHashProvider $hashProvider): void;


	public function setPasswordToken(SecureToken $token): void;


	public function verifyPassword(string $currentPassword, PasswordHashProvider $hashProvider): bool;

}