# Icat CAS authentication plugin

Authenticate with CAS (Central Authentication Service) on Icat.

Note: This was primarly written to work with Topcat's CAS plugin:

* https://github.com/icatproject-contrib/topcat_cas_plugin

## Installation

First you'll need to build copy:

	git clone git@github.com:icatproject-contrib/authn.cas.git
	cd authn.cas
	mvn clean install

next upload the zip file in the target directory unzip it and rename the 'properties' files:

	unzip authn.cas-0.1.0-distro.zip
	cd authn.cas
	cp authn_cas-setup.properties.example authn_cas-setup.properties
	cp authn_cas.properties.example authn_cas.properties

edit the 'properties' files as appropriate and deploy:

	./setup install

