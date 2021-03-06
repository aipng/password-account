<?php

declare(strict_types = 1);

namespace AipNg\Security\PasswordManagement;

use Kdyby\DateTimeProvider\DateTimeProviderInterface;
use Nette\Utils\Random;

final class Md5TokenGenerator implements TokenGenerator
{

	public const DEFAULT_EXPIRATION = 'PT1H';

	/** @var \Kdyby\DateTimeProvider\DateTimeProviderInterface */
	private $dateTimeProvider;

	/** @var \DateInterval */
	private $expirationPeriod;


	public function __construct(DateTimeProviderInterface $dateTimeProvider, ?\DateInterval $interval = null)
	{
		$this->dateTimeProvider = $dateTimeProvider;
		$this->expirationPeriod = $interval ?: new \DateInterval(self::DEFAULT_EXPIRATION);
	}


	public function generate(): SecureToken
	{
		return new SecureToken($this->createRandomToken(), $this->getValidUntil());
	}


	private function createRandomToken(): string
	{
		return md5(Random::generate());
	}


	private function getValidUntil(): \DateTimeImmutable
	{
		return $this->dateTimeProvider->getDateTime()->add($this->expirationPeriod);
	}


	public function setTokenExpirationPeriod(\DateInterval $interval): TokenGenerator
	{
		$this->expirationPeriod = $interval;

		return $this;
	}

}
