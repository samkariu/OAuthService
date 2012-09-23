A simple python library to help you get started with OAuth authentication on
Google Services.Most of this code is derived from the Google Python Client API sample apps.

Make sure you have the Google Python Client API installed in your environment
as follows:
1. Install 'easy_install' python package manager.
2. Run this command 
   $ easy_install --upgrade google-api-python-client

Then copy the lib folder under your root directory.

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