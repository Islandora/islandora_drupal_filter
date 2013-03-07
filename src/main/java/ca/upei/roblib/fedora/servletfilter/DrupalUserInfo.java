/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package ca.upei.roblib.fedora.servletfilter;

//import fedora.common.Constants;
import org.fcrepo.common.Constants;
import java.io.File;
import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author ppound
 * based on fedora xmluserinfo from Fedora commons
 */
class DrupalUserInfo {

    protected static Logger log = LoggerFactory.getLogger(DrupalUserInfo.class);
    private String username = null;
    private String password = null;
    private Boolean authenticated = false;
    private Map namedAttributes = null;
    private String attributeName = null;
    private Set<String> attributeValues = null;
    private final static String ANONYMOUSROLE = "anonymous";

    private Connection connectToDB(String server, String database, String user, String pass, String port) {
        //assuming all drupal installs use mysql as the db.
        if (port == null) {
            port = "3306";
        }
        Connection conn = null;
        try {
            Class.forName("com.mysql.jdbc.Driver").newInstance();
        } catch (Exception ex) {
            log.error("Exception: " + ex.getMessage());

        }

        try {
            conn =
                    DriverManager.getConnection("jdbc:mysql://" + server + ":" + port + "/" + database + "?" +
                    "user=" + user + "&password=" + pass);

        } catch (SQLException ex) {
            // handle any errors
            log.error("SQLException: " + ex.getMessage());
            log.error("SQLState: " + ex.getSQLState());
            log.error("VendorError: " + ex.getErrorCode());
            log.error("Error Connecting to Database server " + server + " port " + port + " database " + database);
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
        String server, database, user, pass, port, sql;
        //we may want to implement a connection pool or something here if performance gets to be
        //an issue.  on the plus side mysql connections are fairly lightweight compared to postgres
        //and the database only gets hit once per user session so we may be ok.
        File drupalConnectionInfo = null;
        namedAttributes = new Hashtable();
        //if the user is anonymous don't check the database just give the anonymous role
        if ("anonymous".equals(userid) && "anonymous".equals(password)) {
            createAnonymousUser();
            return;
        }
        String fedoraHome = Constants.FEDORA_HOME;
        if (fedoraHome == null) {
            log.warn("FEDORA_HOME not set; unable to initialize");
        } else {
            drupalConnectionInfo = new File(fedoraHome, "server/config/filter-drupal.xml");
        }
        if (drupalConnectionInfo == null) {
            log.error("Could not parse drupal filter xml file.");

        }
        Document filterDoc = null;
        try {
            filterDoc = parse(drupalConnectionInfo);
        } catch (DocumentException ex) {
            log.error("Could not parse Drupal Servlet Filter Config file.");

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
                        attributeValues = new HashSet();
                        if (numericId == 0) {
                            attributeValues.add("anonymous");//add the role anonymous in case user in drupal is not associated with any Drupal roles.
                        } else if (numericId == 1) {
                            attributeValues.add("administrator");
                        } else {
                            attributeValues.add("authenticated user");
                        }
                        authenticated = true;
                    }
                    while (hasMoreRecords) {
                        String role = rs.getString("role");
                        if (role != null) {
                            log.debug("DrupalFilter Added role: " + role);
                            attributeValues.add(role);
                        }
                        hasMoreRecords = rs.next();
                    }
                    conn.close();
                }
            } catch (SQLException ex) {
                log.error("Error retrieving user info "+ex.getMessage());
            }

        }

        if (attributeValues != null) {
            namedAttributes.put("fedoraRole", attributeValues);
        }



    }

    public final Boolean getAuthenticated() {
        return authenticated;
    }

    public final Map getNamedAttributes() {
        return namedAttributes;
    }

    private void createAnonymousUser() {
        this.username = "anonymous";
        this.password = "anonymous";
        attributeValues = new HashSet();
        attributeValues.add(DrupalUserInfo.ANONYMOUSROLE);//add the role anonymous in case user in drupal is not associated with any Drupal roles.
        namedAttributes.put("fedoraRole", attributeValues);
        authenticated = true;

    }
}
