/*
 * File: DemoLoginModule.java
 *
 * Copyright 2009 Muradora
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
fedora-auth
{
        org.fcrepo.server.security.jaas.auth.module.XmlUsersFileModule required
        debug=true;

        ca.upei.roblib.fedora.servletfilter.DrupalAuthModule required
        debug=true;
};
 *
 * jaas implementation of the filter.  For fesl authentication
 * configured in jaas.conf see above
 */

package ca.upei.roblib.fedora.servletfilter;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.fcrepo.common.Constants;
import org.fcrepo.server.security.jaas.auth.UserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class DrupalAuthModule
implements LoginModule {

    protected static final Logger logger =
            LoggerFactory.getLogger(DrupalAuthModule.class);

    protected Subject subject = null;

    protected CallbackHandler handler = null;

    protected Map<String, ?> sharedState = null;

    protected Map<String, ?> options = null;

    protected String username = null;

    protected Set<String> attributeValues = null;
    protected Map<String, Set<String>> attributes = null;

    protected final static String ANONYMOUSROLE = "anonymous user";

    protected boolean debug = false;

    protected boolean successLogin = false;

    public void initialize(Subject subject,
            CallbackHandler handler,
            Map<String, ?> sharedState,
            Map<String, ?> options) {
        this.subject = subject;
        this.handler = handler;
        this.sharedState = sharedState;
        this.options = options;

        String debugOption = (String) this.options.get("debug");
        if (debugOption != null && "true".equalsIgnoreCase(debugOption)) {
            debug = true;
        }

        attributes = new HashMap<String, Set<String>>();

        if (debug) {
            logger.debug("login module initialised: " + this.getClass().getName());
        }
    }

    public boolean login() throws LoginException {
        if (debug) {
            logger.debug("DrupalAuthModule login called.");
            for (String key : sharedState.keySet()) {
                String value = sharedState.get(key).toString();
                logger.debug(key + ": " + value);
            }
        }

        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("username");
        callbacks[1] = new PasswordCallback("password", false);

        try {
            handler.handle(callbacks);
            username = ((NameCallback) callbacks[0]).getName();
            char[] passwordCharArray =
                    ((PasswordCallback) callbacks[1]).getPassword();
            String password = new String(passwordCharArray);

            findUser(username, password);

        } catch (IOException ioe) {
            ioe.printStackTrace();
            throw new LoginException("IOException occured: " + ioe.getMessage());
        } catch (UnsupportedCallbackException ucbe) {
            ucbe.printStackTrace();
            throw new LoginException("UnsupportedCallbackException encountered: "
                    + ucbe.getMessage());
        }

        return successLogin;
    }

    public boolean commit() throws LoginException {
        if (!successLogin) {
            return false;
        }

        try {
            UserPrincipal p = new UserPrincipal(username);
            Set<String> roles = attributes.get("role");
            if (roles == null) {
                roles = new HashSet<String>();
                attributes.put("role", roles);
            }

            subject.getPrincipals().add(p);
            subject.getPublicCredentials().add(attributes);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return false;
        }

        return true;
    }

    public boolean abort() throws LoginException {
        try {
            subject.getPrincipals().clear();
            subject.getPublicCredentials().clear();
            subject.getPrivateCredentials().clear();
            username = null;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return false;
        }

        return true;
    }

    public boolean logout() throws LoginException {
        try {
            subject.getPrincipals().clear();
            subject.getPublicCredentials().clear();
            subject.getPrivateCredentials().clear();
            username = null;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return false;
        }

        return true;
    }

    /**
     * @deprecated
     *   Use separate function to parse connection XML element to a Map<String, String>.
     * @param server
     * @param database
     * @param user
     * @param pass
     * @param port
     * @param jdbcDriverClass
     * @param jdbcURLProtocol
     * @return
     */
    @Deprecated
    protected Connection connectToDB(String server, String database, String user, String pass, String port, String jdbcDriverClass, String jdbcURLProtocol) {
        HashMap<String, String> settings = new HashMap<String, String>();
        settings.put("server", server);
        settings.put("database", database);
        settings.put("user", user);
        settings.put("pass", pass);
        settings.put("port", server);
        settings.put("jdbcDriverClass", jdbcDriverClass);
        settings.put("jdbcURLProtocol", jdbcURLProtocol);
        return connectToDB(settings);
    }
    protected Connection connectToDB(Map<String, String> settings) {
        //assuming all drupal installs use mysql as the db.
        Connection conn = null;
        if (settings.get("port") == null) {
            settings.put("port", "3306");
        }

        if (settings.get("jdbcDriverClass") == null) {
            settings.put("jdbcDriverClass", "com.mysql.jdbc.Driver");
        }

        if (settings.get("jdbcURLProtocol") == null) {
            settings.put("jdbcURLProtocol", "jdbc:mysql");
        }

        String jdbcURL = settings.get("jdbcURLProtocol") + "://" +
                settings.get("server") + ":" + settings.get("port") + "/" +
                settings.get("database") + "?" + "user=" + settings.get("user") +
                "&password=" + settings.get("pass");

        try {
            Class.forName(settings.get("jdbcDriverClass")).newInstance();
        } catch (Exception ex) {
            logger.error("Exception: " + ex.getMessage());
        }

        try {
            conn = DriverManager.getConnection(jdbcURL);
        } catch (SQLException ex) {
            // handle any errors
            logger.error("SQLException: " + ex.getMessage());
            logger.error("SQLState: " + ex.getSQLState());
            logger.error("VendorError: " + ex.getErrorCode());
            logger.error("Error Connecting to Database server " + jdbcURL);
            return null;
        }
        return conn;
    }

    /**
     * Get an InputStream containing the config XML.
     *
     * @return
     * @throws IOException
     */
    protected InputStream getConfig() throws IOException {
        String fedoraHome = Constants.FEDORA_HOME;
        if (fedoraHome == null) {
            logger.warn("FEDORA_HOME not set; unable to initialize");
        }

        File file =  new File(fedoraHome, "server/config/filter-drupal.xml");
        return new FileInputStream(file);
    }

    /**
     * Get the parsed XML.
     *
     * @return
     * @throws DocumentException
     * @throws IOException
     */
    protected Document getParsedConfig() throws DocumentException, IOException {
        return getParsedConfig(getConfig());
    }
    protected Document getParsedConfig(File file) throws DocumentException, IOException {
        return getParsedConfig(new FileInputStream(file));
    }
    protected Document getParsedConfig(InputStream stream) throws DocumentException, IOException {
        SAXReader reader = new SAXReader();
        Document document = reader.read(stream);
        return document;
    }

    /**
     * @deprecated
     *   This is only still here because it was public... Just in case.
     * @param file
     * @return
     * @throws DocumentException
     */
    @Deprecated
    public Document parse(File file) throws DocumentException {
        SAXReader reader = new SAXReader();
        Document document = reader.read(file);
        return document;
    }

    protected Map<String, String> parseConnectionElement(Element connection) {
        Map<String, String> toReturn = new HashMap<String, String>();
        toReturn.put("server", connection.attributeValue("server"));
        toReturn.put("database", connection.attributeValue("dbname"));
        toReturn.put("user", connection.attributeValue("user"));
        toReturn.put("pass", connection.attributeValue("password"));
        toReturn.put("port", connection.attributeValue("port"));
        toReturn.put("jdbcDriverClass", connection.attributeValue("jdbcDriverClass"));
        toReturn.put("jdbcURLProtocol", connection.attributeValue("jdbcURLProtocol"));
        Element sqlElement = connection.element("sql");
        toReturn.put("sql", sqlElement.getTextTrim());

        return toReturn;
    }

    /**
     *
     * @param userid
     * @param password
     */
    protected void findUser(String userid, String password) {
        logger.info("login module findUser");

        // If the user is anonymous don't check the database just give the anonymous role.
        if ("anonymous".equals(userid) && "anonymous".equals(password)) {
            createAnonymousUser();
            return;
        }

        Document filterDoc = null;
        try {
            filterDoc = getParsedConfig();
        }
        catch (DocumentException e) {
            logger.error("Failed to parse the configuration XML.");
            return;
        }
        catch (IOException e) {
            logger.error("Failed to load the configuration XML.");
            return;
        }

        @SuppressWarnings("unchecked")
        List<Element> list = filterDoc.selectNodes("//FilterDrupal_Connection/connection");
        Iterator<Element> iter = list.iterator();

        while (iter.hasNext()) {
            try {
                Map<String, String> parsed = parseConnectionElement(iter.next());

                //we may want to implement a connection pool or something here if performance gets to be
                //an issue.  on the plus side mysql connections are fairly lightweight compared to postgres
                //and the database only gets hit once per user session so we may be ok.
                Connection conn = connectToDB(parsed);
                if (conn != null) {
                    PreparedStatement pstmt = conn.prepareStatement(parsed.get("sql"));
                    pstmt.setString(2, password);
                    pstmt.setString(1, userid);
                    ResultSet rs = pstmt.executeQuery();
                    boolean hasMoreRecords = rs.next();
                    if (hasMoreRecords && attributeValues == null) {
                        username = userid;
                        int numericId = rs.getInt("userid");
                        attributeValues = new HashSet<String>();
                        if (numericId == 0) {
                            // Add the role anonymous in case user in drupal is not associated with any Drupal roles.
                            attributeValues.add(DrupalAuthModule.ANONYMOUSROLE);
                            // XXX: Maintain old "anonymous" role, in case it it is actually being used.
                            attributeValues.add("anonymous");
                        } else if (numericId == 1) {
                            attributeValues.add("administrator");
                        }
                        if (numericId > 0) {
                            attributeValues.add("authenticated user");
                        }
                        successLogin = true;
                    }
                    while (hasMoreRecords) {
                        String role = rs.getString("role");
                        if (role != null) {
                            logger.debug("DrupalAuthModule Added role: " + role);
                            attributeValues.add(role);
                        }
                        hasMoreRecords = rs.next();
                    }
                    conn.close();
                }
            } catch (SQLException ex) {
                logger.error("Error retrieving user info "+ex.getMessage());
            }
        }

        attributes.put("role", attributeValues);
    }

    /**
     * Add in attributes for an anonymous user.
     */
    protected void createAnonymousUser() {
        this.username = "anonymous";
        attributeValues = new HashSet<String>();
        // Add the role anonymous in case user in drupal is not associated with any Drupal roles.
        attributeValues.add(DrupalAuthModule.ANONYMOUSROLE);
        // XXX: Maintain old "anonymous" role, in case it it is actually being used.
        attributeValues.add("anonymous");
        attributes.put("role", attributeValues);
        successLogin = true;

    }

}
