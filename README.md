A simple python library to help you get started with OAuth authentication on
Google Services.Most of this code is derived from the Google Python Client API sample apps.

Make sure you have the Google Python Client API installed in your environment
as follows:

1. Install 'easy_install' python package manager.
2. Run this command 
   $ easy_install --upgrade google-api-python-client

Then copy the lib folder under your root directory.

Edit your client_secrets.json (lib/google/client_secrets.json) by inserting you
own client ID, client secret, and list of valid redirect URIs.

The client ID and client secret for an application are created when an application is registered in
the Google APIs Console and the OAuth 2.0 client IDs are generated. You can view these
in the API Access tab of a project.
You can read more from https://developers.google.com/drive/examples/python#setting_up_the_client_id_client_secret_and_other_oauth_20_parameters

In your main application file you can call a basic Google service as follows:

	 from google.services import GoogleServiceHandler
	 # Create a User service
	    service = CreateUserInfo()
	    if service is None:
	      return
	    try:
		#do your stuff
	    except AccessTokenRefreshError:
		#when token isn't refreshed user is redirected
	   	self.RedirectAuth()

You can add more Google Services by creating trivial functions in the
GoogleServiceHandler object in the services.py script under the google package.

e.g adding a new Google Drive service

	def CreateDrive(self):
			"""Create a drive client instance."""
			return self.CreateAuthorizedService('drive', 'v2')