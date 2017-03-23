package ca.upei.roblib.fedora.servletfilter;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.CredentialNotFoundException;
import javax.security.auth.login.LoginException;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;

import ca.upei.roblib.fedora.servletfilter.jaas.KeyChoiceCallback;
import ca.upei.roblib.fedora.servletfilter.jaas.MissingCredsException;

public class DrupalMultisiteAuthModule extends DrupalAuthModule {
    public static final String SUBJECT_ATTRIBUTE_NAME = "islandora-agent";
    protected Map<String, Map<String, String>> config;

    public DrupalMultisiteAuthModule() throws IOException, DocumentException {
        config = new HashMap<String, Map<String, String>>();
        parseConfig();
    }

    protected void parseConfig() throws DocumentException, IOException {
        Document doc = getParsedConfig();
        parseConfig(doc);
    }

    protected void parseConfig(Document doc) {
        config.clear();
        @SuppressWarnings("unchecked")
        List<Element> list = doc.selectNodes("//FilterDrupal_Connection/connection[@key]");
        for (Element el : list) {
            config.put(el.attributeValue("key").trim(), parseConnectionElement(el));
        }
    }

    @Override
    public boolean login() throws LoginException {
        if (debug) {
            logger.debug(String.format("%s login called.", DrupalMultisiteAuthModule.class.getName()));
            for (String key : sharedState.keySet()) {
                String value = sharedState.get(key).toString();
                logger.debug(key + ": " + value);
            }
        }

        String[] keys = config.keySet().toArray(new String[0]);
        NameCallback nc = new NameCallback("username");
        PasswordCallback pc = new PasswordCallback("password", false);
        KeyChoiceCallback kcc = new KeyChoiceCallback(keys);
        Callback[] callbacks = new Callback[] {
                nc, pc, kcc
        };

        try {
            handler.handle(callbacks);
            username = nc.getName();
            char[] passwordCharArray = pc.getPassword();
            String password = new String(passwordCharArray);
            int[] key_selections = kcc.getSelectedIndexes();

            // Should only be exactly one item in key_selections; however,
            // let's iterate for brevity.
            for (int i : key_selections) {
                findUser(username, password, keys[i]);
            }

        }
        catch (IOException ioe) {
            ioe.printStackTrace();
            throw new LoginException("IOException occured: " + ioe.getMessage());
        }
        catch (MissingCredsException mce) {
            throw new CredentialNotFoundException(
                    String.format("Missing \"key\", required for module %s.", this.getClass().getName()));
        }
        catch (UnsupportedCallbackException ucbe) {
            throw new LoginException("UnsupportedCallbackException: " + ucbe.getMessage());
        }

        return successLogin;
    }

    protected void setAgentsSet(String agent) {
        Set<String> agents = new HashSet<String>();
        agents.add(agent);
        attributes.put(SUBJECT_ATTRIBUTE_NAME, agents);
    }

    /**
     *
     * @param userid
     * @param password
     */
    protected void findUser(String userid, String password, String agent) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("Attempting to find %s against %s", userid, agent));
        }
        setAgentsSet(agent);

        // If the user is anonymous don't check the database just give the
        // anonymous role.
        if ("anonymous".equals(userid) && "anonymous".equals(password)) {
            createAnonymousUser();
            return;
        }

        try {
            Map<String, String> parsed = config.get(agent);

            // we may want to implement a connection pool or something here if
            // performance gets to be
            // an issue. on the plus side mysql connections are fairly
            // lightweight compared to postgres
            // and the database only gets hit once per user session so we may be
            // ok.
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
                        // Add the role anonymous in case user in drupal is not
                        // associated with any Drupal roles.
                        attributeValues.add(DrupalMultisiteAuthModule.ANONYMOUSROLE);
                        // XXX: Maintain old "anonymous" role, in case it it is
                        // actually being used.
                        attributeValues.add("anonymous");
                    }
                    else if (numericId == 1) {
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
                        logger.debug(
                                String.format("%s, added role: %s", DrupalMultisiteAuthModule.class.getName(), role));
                        attributeValues.add(role);
                    }
                    hasMoreRecords = rs.next();
                }
                conn.close();
            }
            else if (logger.isDebugEnabled()) {
                logger.debug(String.format("Failed to connect to DB for %s.", agent));
            }
        }
        catch (SQLException ex) {
            logger.error("Error retrieving user info " + ex.getMessage());
        }

        attributes.put("role", attributeValues);
    }
}
