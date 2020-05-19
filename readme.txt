=== WP-WebAuthn ===
Contributors: axton
Donate link: https://flyhigher.top/about
Tags: u2f, fido, fido2, webauthn, login, secure, password
Requires at least: 5.0
Tested up to: 5.4
Stable tag: 1.0.9
Requires PHP: 7.0
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html

WP-WebAuthn enables passwordless login through U2F devices for your site.

== Description ==

WebAuthn is a new way for you to authenticate in web. It helps you replace your passwords with devices like USB Keys, fingerprint scanners, Windows Hello compatible cameras and more.

When using WebAuthn, you just need to click once and perform a simple verification on the authenticator, then you are logged in. **No password needed.**

WP-WebAuthn is a plug-in for WordPress to enable WebAuthn on your site. Just download and install it, and you are in the future of web authentication.

WP-WebAuthn also supports usernameless authentication.

This plugin has 4 built-in shortcodes, so you can add components like register form to frontend pages.

Please refer to the [documentation](http://doc.flyhigher.top/wp-webauthn) before using the plugin.

**PHP extensions gmp and mbstring are required.**

**WebAuthn requires HTTPS connection or `localhost` to function normally.**

You can contribute to this plugin on [GitHub](https://github.com/yrccondor/wp-webauthn).

== Installation ==

Notice: PHP extensions gmp and mbstring are required.

1. Upload the plugin files to the `/wp-content/plugins/wp-webauthn` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress
3. Use the Settings->WP-WebAuthn screen to configure the plugin
4. Make sure that all settings are set, and you can start to register authenticators

== Frequently Asked Questions ==
 
= What languages does this plugin support? =
 
This plugin supports English and Chinese(Simplified) currently. If you are using WordPress in none of those languages, English will be displayed as default language.

All translation files are hosted on [GitHub](https://github.com/yrccondor/wp-webauthn/tree/master/languages). You can help us to translate WP-WebAuthn into other languages!

= What should I do if the plugin could not work? =
 
Make sure your are using HTTPS or host your site in `localhost`. Then ckeck whether you have installed the gmp extension for PHP.

If you can't solve the problem, [open an issue](https://github.com/yrccondor/wp-webauthn/issues/new) on [GitHub](https://github.com/yrccondor/wp-webauthn) with plugin log.
 
= Which browsers support WebAuthn? =
 
The latest version of Chrome, FireFox, Edge and Safari are support WebAuthn. You can learn more on [Can I Use](https://caniuse.com/#feat=webauthn).

== Screenshots ==

1. Verifying
2. The login page
3. The settings page

== Changelog ==

= 1.0.9 =
Add: Login without usernameless
Add: Last used
Update: Third-party libraries
Improve: Delete authenticators when deleting user
Improve: Destroy all sessions before wp_die() or at the end of authentications
Improve: Log traceback
Improve: i18n

= 1.0.8 =
Improve: Compatibility with Two Factor plugin

= 1.0.7 =
Fix: WebAuthn disabled by mistake on iOS devices
Fix: Plug-in not initialized correctly when being actived
Fix: Failed to register authenticators on Firefox and Microsoft Edge
Fix: Wrong timezone when registering authenticator
Add: Authenticator rename
Add: 4 shortcodes
Add: Log
Update: Third-party libraries
Improve: Allow bypass HTTPS check when under localhost
Improve: Remove jQuery dependence on login page

= 1.0.6 =
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

= 1.0.9 =
Improve security & add usernameless login and other features

= 1.0.8 =
Improve: Compatibility with Two Factor plugin

= 1.0.7 =
Bug fix, Improved compatibility & new features

= 1.0.6 =
Improved compatibility in login page & Bug fix

= 1.0.4 =
Improved compatibility in login page & Bug fix

= 1.0.3 =
Bug fix

= 1.0.2 =
Initial version