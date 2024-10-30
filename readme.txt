=== Login Protection ===
Contributors: couhie
Tags: security, login, password, attack, hack, lock, authentication, auth, brute, force, brute force
Requires at least: 3.0
Tested up to: 3.5
Stable tag: 0.2.5

This plugin make improve the security of the administration page by blocking unauthorized access.


== Description ==

Protect the administration page from unauthorized access.

In addition, you can also protect the management page by basic authentication.

To make inaccessible with unauthorized to the administration page by blocking the Ip address of failed to authentication continuously.

If you became to can not login yourself to admin page, please remove the `/wp-content/plugins/login-protection/cache/enabled` file. Block is released. Please update the setting again after login.

Also support multisite.

== Installation ==

1. Upload `login-protection` directory to the `/wp-content/plugins/` directory.

1. Activate the plugin through the 'Plugins' menu in WordPress.

== Frequently Asked Questions ==
None.

== Screenshots ==
None.

== Changelog ==

= 0.2.5 =
* Changed the readme.

= 0.2.4 =
* Supported Japanese.

= 0.2.3 =
* Changed the readme.

= 0.2.2 =
* Added the URL information of the plugin.

= 0.2.1 =
* Bug fix.

= 0.2.0 =
* Without using the basic authentication, it was changed to be able to block unauthorized access.

= 0.1.7 =
* Modified to changed the http status code to return when it is blocked.

= 0.1.6 =
* Modified to be able to set the interval to reset the continuous authentication failure count.

= 0.1.5 =
* Modified to keep the date and time that fail authentication.

= 0.1.4 =
* Modified to be able to set the time to block the authentication.

= 0.1.3 =
* Added a way to disable the available authentication in case you forget the password or user for Basic authentication.

= 0.1.2 =
* Modified to not block when 0 is set to "Block threshold".

= 0.1.1 =
* Modified to use prepare() with queries to protect from SQL injection vulnerabilities.

= 0.1.0 =
* First release edition.

== Arbitrary section ==
None.
