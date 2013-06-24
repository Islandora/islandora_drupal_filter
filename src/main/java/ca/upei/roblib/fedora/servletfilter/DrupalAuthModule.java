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

import org.fcrepo.common.Constants;

import java.io.IOException;
import java.io.File;

import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;

import java.util.Iterator;
import java.util.List;
import java.util.Hashtable;
import java.util.HashMap;
import java.util.HashSet;
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

import org.fcrepo.server.security.jaas.auth.UserPrincipal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;


public class DrupalAuthModule
        implements LoginModule {

    private static final Logger logger =
            LoggerFactory.getLogger(DrupalAuthModule.class);

    private Subject subject = null;

    private CallbackHandler handler = null;

    private Map<String, ?> sharedState = null;

    private Map<String, ?> options = null;

    private String username = null;
    private String password = null;

    private Set<String> attributeValues = null;
    private Map<String, Set<String>> attributes = null;

    private final static String ANONYMOUSROLE = "anonymous user";

    private boolean debug = false;

    private boolean successLogin = false;

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

	    this.findUser(username,password);

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

    private Connection connectToDB(String server, String database, String user, String pass, String port) {
        //assuming all drupal installs use mysql as the db.
        if (port == null) {
            port = "3306";
        }
        Connection conn = null;
        try {
            Class.forName("com.mysql.jdbc.Driver").newInstance();
        } catch (Exception ex) {
            logger.error("Exception: " + ex.getMessage());

        }

        try {
            conn =
                    DriverManager.getConnection("jdbc:mysql://" + server + ":" + port + "/" + database + "?" +
                    "user=" + user + "&password=" + pass);

        } catch (SQLException ex) {
            // handle any errors
            logger.error("SQLException: " + ex.getMessage());
            logger.error("SQLState: " + ex.getSQLState());
            logger.error("VendorError: " + ex.getErrorCode());
            logger.error("Error Connecting to Database server " + server + " port " + port + " database " + database);
            return null;
        }
        return conn;
    }

    public Document parse(File file) throws DocumentException {
        SAXReader reader = new SAXReader();
        Document document = reader.read(file);
        return document;
    }

    void findUser(String userid, String password) {
    	logger.info("login module findUser");
    	String server, database, user, pass, port, sql;
        //we may want to implement a connection pool or something here if performance gets to be
        //an issue.  on the plus side mysql connections are fairly lightweight compared to postgres
        //and the database only gets hit once per user session so we may be ok.
        File drupalConnectionInfo = null;

        // If the user is anonymous don't check the database just give the anonymous role.
        if ("anonymous".equals(userid) && "anonymous".equals(password)) {
            createAnonymousUser();
            return;
        }
        String fedoraHome = Constants.FEDORA_HOME;
        if (fedoraHome == null) {
            logger.warn("FEDORA_HOME not set; unable to initialize");
        } else {
            drupalConnectionInfo = new File(fedoraHome, "server/config/filter-drupal.xml");
        }
        if (drupalConnectionInfo == null) {
            logger.error("Could not parse drupal filter xml file.");

        }
        Document filterDoc = null;
        try {
            filterDoc = parse(drupalConnectionInfo);
        } catch (DocumentException ex) {
            logger.error("Could not parse Drupal Servlet Filter Config file.");

        }
        List list = filterDoc.selectNodes("//FilterDrupal_Connection/connection");
        Iterator iter = list.iterator();

        while (iter.hasNext()) {
            try {
                Element connection = (Element) iter.next();
                server = connection.attributeValue("server");
                database = connection.attributeValue("dbname");
                user = connection.attributeValue("user");
                pass = connection.attributeValue("password");
                port = connection.attributeValue("port");
                Element sqlElement = connection.element("sql");
                sql = sqlElement.getTextTrim();
                Connection conn = connectToDB(server, database, user, pass, port);
                if (conn != null) {
                    PreparedStatement pstmt = conn.prepareStatement(sql);
                    pstmt.setString(2, password);
                    pstmt.setString(1, userid);
                    ResultSet rs = pstmt.executeQuery();
                    boolean hasMoreRecords = rs.next();
                    if (hasMoreRecords && attributeValues == null) {
                        username = userid;
                        int numericId = rs.getInt("userid");
                        this.password = password;
                        attributeValues = new HashSet<String>();
                        if (numericId == 0) {
                            // Add the role anonymous in case user in drupal is not associated with any Drupal roles.
                            attributeValues.add(DrupalAuthModule.ANONYMOUSROLE);
                            // XXX: Maintain old "anonymous" role, in case it it is actually being used.
                            attributeValues.add("anonymous");
                        } else if (numericId == 1) {
                            attributeValues.add("administrator");
                        } else {
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


    private void createAnonymousUser() {
        this.username = "anonymous";
        this.password = "anonymous";
        attributeValues = new HashSet<String>();
        // Add the role anonymous in case user in drupal is not associated with any Drupal roles.
        attributeValues.add(DrupalAuthModule.ANONYMOUSROLE);
        // XXX: Maintain old "anonymous" role, in case it it is actually being used.
        attributeValues.add("anonymous");
        attributes.put("role", attributeValues);
        successLogin = true;

    }






}
