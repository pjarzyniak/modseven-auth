Modseven Auth Module
This is the official Auth Module for Modseven.

Why seperate repo?
In Koseven modules are directly in the main repo, for modseven this is no longer necessary, all modules can be included via composer.

Installation
composer require modseven/auth ..that's it.

Configuration
Copy the file(s) from vendor/modseven/auth/conf/ to your application/conf folder. Modify them as needed. Caution: In Koseven the configurations get combined with each other starting from APPATH to SYSPATH this is NOT the case anymore so make sure you copy all contents of the configuration file.

Usage
Namespace is \Modseven\Auth, except that it works pretty much like the original one form Kosevevn - Doku