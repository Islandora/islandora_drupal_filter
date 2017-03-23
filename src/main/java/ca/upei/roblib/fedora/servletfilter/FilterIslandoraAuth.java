package ca.upei.roblib.fedora.servletfilter;

import java.io.File;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.FilterConfig;

import org.apache.commons.codec.binary.Base64;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.fcrepo.common.Constants;
import org.fcrepo.server.security.servletfilters.BaseCaching;
import org.fcrepo.server.security.servletfilters.Cache;
import org.fcrepo.server.security.servletfilters.CacheElement;
import org.fcrepo.server.security.servletfilters.ExtendedHttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**filter used exclusively for djatoka with api-a locked down.
 * for use in non fesl base sites.  configured in web.xml
 */
@SuppressWarnings({
    "unchecked", "deprecation"
})
public class FilterIslandoraAuth extends BaseCaching {
    private static final String PARAMETER_NAME_UID = "uid";
    private static final Credentials DJATOKA_CREDENTIALS = new Credentials("djatoka", "djatoka");
    private Set<String> djatokaIPs;
    private String djatokaURIPattern;
    private Set<String> djatokaRoles;
    protected static Logger log = LoggerFactory.getLogger(FilterDrupal.class);

    static class Credentials {
        String password;
        String user;

        Credentials(String user, String password) {
            this.user = user;
            this.password = password;
        }
    }

    @Override
    public void init(FilterConfig filterConfig) {
        super.init(filterConfig);
        readConfigurationXml();
    }

    private void readConfigurationXml() {
        try {
            String fedoraHome = Constants.FEDORA_HOME;
            File file = new File(fedoraHome, "server/config/filter-drupal.xml");
            SAXReader reader = new SAXReader();
            Document doc = reader.read(file);
            Element djatoka = (Element) doc.selectSingleNode("//service[@name='djatoka']");
            String ips = djatoka.elementTextTrim("allowed_ips");
            djatokaIPs = new HashSet<String>(Arrays.asList(ips.split("\\s+")));
            djatokaURIPattern = djatoka.elementTextTrim("allowed_uri_pattern");
            String roles = djatoka.elementTextTrim("roles");
            djatokaRoles = new HashSet<String>(Arrays.asList(roles.split("\\s")));
        }

        catch (Exception e) {
            //showThrowable(e, log, "error reading read config file");
            log.error("error reading config file " + e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    @Override
    public void authenticate(
            ExtendedHttpServletRequest extendedHttpServletRequest)
                    throws Exception {
        Credentials credentials = getCredentials(extendedHttpServletRequest);
        //log.info("User: " + credentials.user + " Password : " + credentials.password);
        if (credentials != null) {
            Cache cache = getCache(FILTER_NAME);

            try {
                Boolean result = cache.authenticate(this, credentials.user,
                        credentials.password);
                if (result != null && result.booleanValue()) {
                    Principal authenticatingPrincipal = new org.fcrepo.server.security.servletfilters.Principal(
                            credentials.user);
                    extendedHttpServletRequest.setAuthenticated(
                            authenticatingPrincipal, FILTER_NAME);
                }

                cache.audit(credentials.user);
            }

            catch (Throwable e) {
                throw new Exception(e);
            }
        }
    }

    @Override
    public void contributeAuthenticatedAttributes(
            ExtendedHttpServletRequest extendedHttpServletRequest)
                    throws Exception {
        if (extendedHttpServletRequest.getUserPrincipal() != null) {
            Credentials c = getCredentials(extendedHttpServletRequest);
            contributeAttributes(extendedHttpServletRequest, c.user, c.password);
        }
    }

    @Override
    public void populateCacheElement(CacheElement cacheElement, String password) {
        if (isDjatokaRequest(cacheElement.getUserid(), password)) {
            log.info("authenticating djatoka request");
            populateCacheElementForServiceRequest(cacheElement);
        }

        else {
            log.info("authenticating user request for: " + cacheElement.getUserid()  + " Password: " + password);
            DrupalUserInfo parser = new DrupalUserInfo();
            log.info("User ID: " + cacheElement.getUserid());
            try {
                parser.findUser(cacheElement.getUserid(), password);
            }

            catch (Exception e) {
                //showThrowable(e, log, "error querying database");
                log.error("error querying database "+e.getLocalizedMessage());
            }

            cacheElement.populate(parser.getAuthenticated(), null, parser
                    .getNamedAttributes(), null);
        }
    }

    private void populateCacheElementForServiceRequest(CacheElement cacheElement) {
        Map<String, Set<?>> attributeMap = new HashMap<String, Set<?>>();
        attributeMap.put("fedoraRole", djatokaRoles);
        cacheElement.populate(Boolean.TRUE, null, attributeMap, null);
    }

    private Credentials getCredentials(
            ExtendedHttpServletRequest extendedHttpServletRequest) {
        Credentials credentials = null;

        if (isDjatokaRequest(extendedHttpServletRequest)) {
            credentials = DJATOKA_CREDENTIALS;
        }

        else {
            String uid = extendedHttpServletRequest.getParameter(PARAMETER_NAME_UID);
            if (uid != null || "".equals(uid)) {
                String decoded = decode(uid);
                String[] parts = decoded.split(":");

                if (parts.length == 2) {
                    credentials = new Credentials(parts[0], parts[1]);
                }
            }
        }

        return credentials;
    }

    private boolean isDjatokaRequest(String user, String password) {
        return DJATOKA_CREDENTIALS.user.equals(user) && DJATOKA_CREDENTIALS.password.equals(password);
    }

    private boolean isDjatokaRequest(
            ExtendedHttpServletRequest extendedHttpServletRequest) {

        boolean local = false, jp2 = false;
        try {
            local = djatokaIPs.contains(extendedHttpServletRequest.getRemoteAddr())
                    || (djatokaIPs.contains("local") && extendedHttpServletRequest
                            .getRemoteAddr().equals(
                                    extendedHttpServletRequest.getLocalAddr()));

            jp2 = extendedHttpServletRequest.getRequestURI().matches(djatokaURIPattern);
        }

        catch (Exception e) {
            //showThrowable(e, log, "error assessing service request");
            log.error("error assessing service request "+e.getLocalizedMessage());
        }

        return local && jp2;
    }

    private String decode(String uid) {
        byte[] encodedBytes = uid.getBytes();
        byte[] decodedBytes = Base64.decodeBase64(encodedBytes);
        String decoded = new String(decodedBytes);
        return decoded;
    }
}
