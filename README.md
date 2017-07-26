Password account
================

[![Build Status](https://travis-ci.org/aipng/password-account.svg?branch=master)](https://travis-ci.org/aipng/password-account)

Provides basic manipulation with password based accounts.

Installation
------------

The best way to install package is using [Composer](http://getcomposer.org/):

```sh
$ composer require aipng/password-account
```

Using Nette extension
---------------------

When using in application based on Nette, you should enable provided extension using your neon configuration file.

```yml
extensions:
  passwordAccount: AipNg\Security\DI\PasswordAccountExtension
```

Configuration
-------------

When using default token generator, based on MD5 algorithm, you can configure token expiration in minutes (somewhere in your configuration file):

```yml
passwordAccount:
  md5TokenExpiration: 60    # 60 minutes by default
```

In case you want to use your own implementation of token generator, this option is useless.

If you want to use default password hash provider, based on PHP's `password_hash` and `password_verify` functions, you can set the algorithmic cost:

```yml
passwordAccount:
  passwordCost: 10    # 10 by default
```
