<?php

declare(strict_types = 1);

namespace AipNg\Security\Events;

use AipNg\Security\PasswordManagement\GeneratedToken;
use Symfony\Component\EventDispatcher\Event;

final class AccountTokenGeneratedEvent extends Event
{

	/** @var \AipNg\Security\PasswordManagement\GeneratedToken */
	private $generatedToken;


	public function __construct(GeneratedToken $generatedToken)
	{
		$this->generatedToken = $generatedToken;
	}


	public function getGeneratedToken(): GeneratedToken
	{
		return $this->generatedToken;
	}

}
