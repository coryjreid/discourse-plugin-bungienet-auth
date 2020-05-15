## discourse-plugin-bungienet-auth

This plugin allows you to utilize Bungie.net's OAuth interface to let users
authenticate with your Discourse instance. This plugin is a fork of 
[discourse oauth2 basic](https://github.com/discourse/discourse-oauth2-basic) 
without which this plugin would not exist. You can also look for other login 
providers in Discourse's [Github Repo](https://github.com/discourse).


## Usage

### Basic Configuration

First, set up your Discourse application on Bungie.net via the 
[developer portal](https://www.bungie.net/en/Application).

* **OAuth Client Type** should be `Confidential`
* **Redirect URL** should be `https://<forum_domain>/auth/bungienet/callback`  \
  Note: HTTPS is required by Bungie.net!

Visit your **Admin** > **Settings** > **Login** and fill in the following at minimum:

* `bungienet_enabled` - Enable login with Bungie.net
* `bungienet_api_key` - The Application API Key
* `bungienet_client_id` - The Application OAuth client_id
* `bungienet_client_secret` - The Application OAuth client_secret

Assuming Bungie.net hasn't changed their API in a way that breaks any of the defaults
this should be all you need. In the event they have changed something, it is assumed
you can figure out the correct paths on your own. If you need help feel free to open
an issue.

## License

MIT
