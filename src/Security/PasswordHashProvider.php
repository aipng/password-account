<?php

declare(strict_types = 1);

namespace AipNg\Security;

interface PasswordHashProvider
{

	public function verifyPassword(string $password, string $hash): bool;


	public function hashPassword(string $password): string;

}
