<?php

declare(strict_types = 1);

namespace AipNg\Security;

final class DefaultHashProvider implements
	\AipNg\Security\PasswordHashProvider
{

	/** @var int */
	private $passwordCost;


	public function __construct(?int $passwordCost = 12)
	{
		$this->passwordCost = $passwordCost;
	}


	public function verifyPassword(string $password, string $hash): bool
	{
		return password_verify($password, $hash);
	}


	public function hashPassword(string $password): string
	{
		return password_hash($password, PASSWORD_DEFAULT, ['cost' => $this->passwordCost]);
	}


	public function getPasswordCost(): int
	{
		return $this->passwordCost;
	}


	public function changePasswordCost(int $passwordCost): void
	{
		$this->passwordCost = $passwordCost;
	}

}
