# Multisite Optimization Configuration

There are a number of moving parts:

* JAAS implementation to acquire additional context (the header)
* LoginModule implementation to _use_ the additional context
* Connection configuration in the LoginModule (to inform the use of the context)
* Header configuration from clients (the context provided from the client)

A few definitions, just for ease of discussion:

| Name | Example | Description |
| ---- | ------- | ----------- |
| `$FEDORA_HOME` | `/usr/local/fedora` | Path to the Fedora installation. |
| `$CATALINA_HOME` | `/usr/local/fedora/tomcat` | Path to the instance of Tomcat in which Fedora is installed. |

## Filter installation

Assuming Fedora is installed with the path `fedora`, installation should just require dropping the built JAR into `$CATALINA_HOME/webapps/fedora/WEB-INF/lib`.

## JAAS implementation integration

To make Fedora use our JAAS implementation, alter `AuthFilterJAAS` bean defined in `$FEDORA_HOME/server/config/security/web.xml` to use our class `ca.upei.roblib.fedora.servletfilter.jaas.AuthFilterJAAS` instead of `org.fcrepo.server.security.jaas.AuthFilterJAAS`.

```xml
[...]
<!-- The "class" attribute here is what has been changed -->
<bean id="AuthFilterJAAS" class="ca.upei.roblib.fedora.servletfilter.jaas.AuthFilterJAAS"
  [...]>
  <!-- Default; insert uncommented to change the header used.
  <property name="keyHeader" value="User-Agent"/>
  -->
</bean>
```

## LoginModule

The configuration of modules is done in `$FEDORA_HOME/server/config/jaas.conf` by default. In the `fedora-auth` section, we need to introduce our `ca.upei.roblib.fedora.servletfilter.DrupalMultisiteAuthModule`. Ideally, this should look something like:

```
fedora-auth
{
        org.fcrepo.server.security.jaas.auth.module.XmlUsersFileModule sufficient
        debug=true;
        ca.upei.roblib.fedora.servletfilter.DrupalMultisiteAuthModule sufficient
        debug=true;
};
```

This configuration results in a fall-through behaviour, which means that the first match is used from:

* `$FEDORA_HOME/server/config/fedora-users.xml`,
* the connection for the site matching our key.

If desirable, the `ca.upei.roblib.fedora.servletfilter.DrupalAuthModule` might be left in as the last module to attempt, to fallback to scanning across _all_ of the configured connections:

```
fedora-auth
{
        org.fcrepo.server.security.jaas.auth.module.XmlUsersFileModule sufficient
        debug=true;
        ca.upei.roblib.fedora.servletfilter.DrupalMultisiteAuthModule sufficient
        debug=true;
        ca.upei.roblib.fedora.servletfilter.DrupalAuthModule sufficient
        debug=true;
};
```

## Connection configuration

Connections for consideration in the `DrupalMultisiteAuthModule` _must_ have unique `key` attributes in the `$FEDORA_HOME/server/config/filter-drupal.xml` (should a key not be unique, it is likely the last configured connection with the key would be used).

```xml
<?xml version="1.0" encoding="UTF-8"?>
<FilterDrupal_Connection>
  <connection key="test_key" [... other configuration attributes ...]>
      <sql>
        [...]
      </sql>
    </connection>
</FilterDrupal_Connection>
```

In the above (shortened) example, the key would be "test_key".

## Client request headers

There's no precise mechanism prescribed to set the header. Assuming the default header of `User-Agent` is being manipulated, something like [`islandora_repository_connection_config`](https://github.com/discoverygarden/islandora_repository_connection_config) might be used on each site, or a custom implementation of the underlying `hook_islandora_repository_connection_construction_alter()`.

While the ability to extract the key from other headers has been allowed in the LoginModule, the exact mechanism which might be use to inject arbitrary headers has not been examined in any great amount.

In any case, the header passed needs to match those configured in the [Connection configuration](#connection-configuration) above, in our case "test_key".
