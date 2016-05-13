Roles
=====

These are the roles we use for deploying

To sync with amazon:

* Make your changes

Then sync production::

        $ credo -a prod inject # Or how however you get credentials
        $ ./deploy/roles/syncr deploy/roles/prod

And for staging::

        $ credo -a stg inject # Or how however you get credentials
        $ ./deploy/roles/syncr deploy/roles/stg

