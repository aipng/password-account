<?php

declare(strict_types = 1);

namespace AipNg\Security\PasswordManagement;

interface TokenGenerator
{

	public function generate(): SecureToken;


	public function setTokenExpirationPeriod(\DateInterval $interval): TokenGenerator;

}
