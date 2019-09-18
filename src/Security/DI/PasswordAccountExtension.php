<?php

declare(strict_types = 1);

namespace AipNg\Security\DI;

use AipNg\Security\DefaultHashProvider;
use AipNg\Security\PasswordAuthenticator;
use AipNg\Security\PasswordHashProvider;
use AipNg\Security\PasswordManagement\AccountTokenFacade;
use AipNg\Security\PasswordManagement\Md5TokenGenerator;
use AipNg\Security\PasswordManagement\PasswordFacade;
use AipNg\Security\PasswordManagement\TokenGenerator;
use Kdyby\DateTimeProvider\DateTimeProviderInterface;
use Nette\DI\CompilerExtension;
use Nette\DI\MissingServiceException;
use Nette\DI\Statement;

final class PasswordAccountExtension extends CompilerExtension
{

	/** @var mixed[] */
	private $defaults = [
		'md5TokenExpiration' => 60,
		'passwordCost' => 10,
	];


	public function loadConfiguration(): void
	{
		$this->validateConfig($this->defaults);

		$builder = $this->getContainerBuilder();

		try {
			$builder->getDefinitionByType(DateTimeProviderInterface::class);
		} catch (MissingServiceException $e) {
			$this->addDefaultDateTimeProvider();
		}

		try {
			$builder->getDefinitionByType(TokenGenerator::class);
		} catch (MissingServiceException $e) {
			$this->addDefaultTokenGenerator($this->config['md5TokenExpiration']);
		}

		try {
			$builder->getDefinitionByType(PasswordHashProvider::class);
		} catch (MissingServiceException $e) {
			$this->addDefaultHashProvider($this->config['passwordCost']);
		}

		$builder
			->addDefinition($this->prefix('accountTokenFacade'))
			->setClass(AccountTokenFacade::class);

		$builder
			->addDefinition($this->prefix('passwordFacade'))
			->setClass(PasswordFacade::class);

		$builder
			->addDefinition($this->prefix('passwordAuthenticator'))
			->setClass(PasswordAuthenticator::class);
	}


	private function addDefaultDateTimeProvider(): void
	{
		$this
			->getContainerBuilder()
			->addDefinition($this->prefix('dateTimeProvider'))
			->setClass(DateTimeProviderInterface::class);
	}


	private function addDefaultTokenGenerator(int $expirationInMinutes): void
	{
		$this
			->getContainerBuilder()
			->addDefinition($this->prefix('tokenGenerator'))
			->setClass(Md5TokenGenerator::class, [
				new Statement('@' . $this->prefix('dateTimeProvider')),
				new \DateInterval(sprintf('PT%dM', $expirationInMinutes)),
			]);
	}


	private function addDefaultHashProvider(int $passwordCost): void
	{
		$this
			->getContainerBuilder()
			->addDefinition($this->prefix('hashProvider'))
			->setClass(DefaultHashProvider::class, [$passwordCost]);
	}

}
