=== WP-WebAuthn ===
Contributors: axton
Donate link: https://flyhigher.top/about
Tags: u2f, fido, fido2, webauthn, login, secure, password
Requires at least: 5.0
Tested up to: 5.4
Stable tag: trunk
Requires PHP: 7.0
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html

WP-WebAuthn enables passwordless login through U2F devices for your site.

== Description ==

WebAuthn is a new way for you to authenticate in web. It helps you replace your passwords with devices like USB Keys, fingerprint scanners, Windows Hello compatible cameras and more.

When using WebAuthn, you just need to click once and perform a simple verification on the authenticator, then you are logged in. **No password needed.**

WP-WebAuthn is a plug-in for WordPress to enable WebAuthn on your site. Just download and install it, and you are in the future of web authentication.

**PHP extension gmp is required.**

**WebAuthn requires HTTPS connection or `localhost` to function normally.**

== Installation ==

Notice: PHP extension gmp is required.

1. Upload the plugin files to the `/wp-content/plugins/wp-webauthn` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress
3. Use the Settings->WP-WebAuthn screen to configure the plugin
4. Make sure that all settings are set, and you can start to register authenticators

== Frequently Asked Questions ==
 
= What should I do if the plugin could not work? =
 
Make sure your are using HTTPS or host your site in `localhost`. Then ckeck whether you have installed the gmp extension for PHP.

== Screenshots ==

1. The login page
2. The settings page

== Changelog ==

= 1.0.5 =
Fix: Auth button displays in register form
Improve: Set English as default language
Improve: Compatibility in login page

= 1.0.4 =
Fix: Auth button displays in forget password form
Fix: Test button disabled by fault
Improve: Compatibility in login page

= 1.0.3 =
Fix: Login button disabled by fault when WebAuthn is not available
Fix: The Auth button has zero width when the login page is modified
Fix: iOS users may be failed to register authenticators due to the user verification policy

= 1.0.2 =
Initial version

== Upgrade Notice ==

= 1.0.5 =
Improved compatibility in login page & Bug fix

= 1.0.4 =
Improved compatibility in login page & Bug fix

= 1.0.3 =
Bug fix

= 1.0.2 =
Initial version