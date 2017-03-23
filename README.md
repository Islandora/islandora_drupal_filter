Islandora Drupal Servlet Filter

Description
===========

This is the servlet filter to permit the Fedora Commons repository software to authenticate against a Drupal database. Both FeSL (JAAS) and non-FeSL authentication schemes are supported with the same .jar file.

For help with configuring the Drupal filter see the servlet_filter_README.txt file in the Islandora download distribution.

Anonymous Users
===============
Fedora requires a username for the audit trail so we populate a username of anonymous for empty user names.

Drupal Version
==============

The same version of the filter will work for both Drupal 6 and Drupal 7 Islandora installations.

Building
========

This project uses Maven and specifies Fedora as a dependency.  To build the servlet filter simply run the command:

    mvn package

To build for a specific version of Fedora, the `fedora.version` parameter can be passed (defaults to 3.6.2), so to build for Fedora 3.7.1, you could call:

    mvn package -Dfedora.version=3.7.1

This can take a few minutes as Maven will need to download and build Fedora before it can build the Drupal filter.

To remove traces of the build process, run:

    mvn clean

The `target/` directory is in the `.gitignore` file as it is bad practise to check binary files into Git that are created with a build process.

Multisite Optimization
=======================

The original `DrupalAuthModule` implementation requires iterating through all configured connection when authenticating users, and for repositories connected to many sites, this iteration can be slow (and unavailable sites may even result in timeouts); therefore, it is desirable if it was possible to more directly select which against which to attempt authentication.

The `DrupalMultisiteAuthModule` looks for `key` attributes on each connection element, which must match the `key` obtained from the HTTP request in our `ca.upei.roblib.fedora.servletfilter.jaas.AuthFilterJAAS` implementation (by default, the `User-Agent` header because it is easily modified for requests from Tuque; configurable to other headers using the `keyHeader` property in the Spring bean configuration).

See [the documentation](/docs/multisite-optimization.md) for more details.
