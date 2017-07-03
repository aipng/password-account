<?php

declare(strict_types = 1);

namespace AipNg\Security\PasswordManagement;

final class SecureToken
{

	/** @var string */
	private $token;

	/** @var \DateTimeImmutable */
	private $validUntil;


	public function __construct(string $token, \DateTimeImmutable $validUntil)
	{
		$this->token = $token;
		$this->validUntil = $validUntil;
	}


	public function getToken(): string
	{
		return $this->token;
	}


	public function getValidUntil(): \DateTimeImmutable
	{
		return $this->validUntil;
	}

}
