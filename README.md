<html>
<body>
<strong>Plugin Name: Custom Login & SSO
Description: A WordPress plugin for API login and Single Sign-On.
Version: 1.0
Author: Shantanu Goswami
</strong>
<h3>Instructions:</h3>

After downloading the plugin you need to do 
<b>composer install</b>
to install all dependencies. 
Also you need Google OAuth Credentials
for now use test environment and user <b>shaanjyot13@gmail.com</b> was used for testing.

<h3>Get Go0gle OAuth Credentials:</h3>
<ul>
<li>Go to the Google Cloud Console.
Select your project.
Configure OAuth Consent Screen:</li>
<li>
In the left navigation pane, go to "APIs & Services" > "OAuth consent screen."
Configure the OAuth consent screen details, such as your app's name and user support email.
Authorized Domains:</li>

<li>Scroll down to the "Authorized Domains" section.
Add the domain where your WordPress site is hosted (e.g., example.com) as an authorized domain.
Authorized JavaScript Origins:</li>

<li>In the "Authorized JavaScript Origins" section, click on "Add URI."
Add the base URL of your WordPress site, including the protocol (e.g., https://example.com).
Authorized Redirect URIs:</li>

<li>In the "Authorized Redirect URIs" section, click on "Add URI."
Add the full redirect URI where your OAuth callback endpoint is located (e.g., https://example.com/oauth-callback).
Save Changes:</li>
<ul>

Save your OAuth consent screen configuration.

<h3>Custom Endpoints are:</h3>

1) https://yourwebsite.com/wp-json/custom-login/v1/
2) https://yourwebsite.com/wp-json/custom-login/v1/sso/google
</body>
</html>
