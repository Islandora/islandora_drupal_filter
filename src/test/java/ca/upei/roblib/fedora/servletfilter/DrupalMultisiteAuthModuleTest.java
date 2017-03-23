package ca.upei.roblib.fedora.servletfilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.dom4j.DocumentException;

import junit.framework.TestCase;

public class DrupalMultisiteAuthModuleTest extends TestCase {
    protected DrupalMultisiteAuthModule mockInstance;
    protected final String KEY = "test_key";

    @SuppressWarnings({
        "unchecked", "rawtypes"
    })
    @Override
    public void setUp() throws Exception {
        super.setUp();

        mockInstance = new DrupalMultisiteAuthModuleMock();
        mockInstance.initialize(new Subject(), new MockHandler(), new HashMap(), new HashMap());
    }

    public void testFindUserUserOneHasAdministratorRole() {
        mockInstance.findUser("alpha", "first", KEY);
        assertTrue("User \"1\" gets the \"administrator\" role", mockInstance.attributeValues.contains("administrator"));
    }

    public void testFindUserAnonymous() {
        mockInstance.findUser("anonymous", "anonymous", KEY);
        assertTrue("Anonymous gets the anonymous role", mockInstance.attributeValues.contains(DrupalAuthModule.ANONYMOUSROLE));
    }

    @SuppressWarnings({
        "rawtypes", "unchecked"
    })
    public void testFindUserAuthenticatedUser() throws IOException, DocumentException {
        Map<String,String> users = new HashMap<String, String>();
        users.put("alpha", "first");
        users.put("bravo", "second");
        users.put("charlie", "third");

        for (String key: users.keySet()) {
            mockInstance = new DrupalMultisiteAuthModuleMock();
            mockInstance.initialize(new Subject(), new MockHandler(), new HashMap(), new HashMap());
            mockInstance.findUser(key, users.get(key), KEY);
            mockInstance.attributeValues.contains("authenticated user");
        }
    }

    public void testFindUserAlphaConfiguredRoles() {
        mockInstance.findUser("alpha", "first", KEY);
        assertTrue("Alpha has proper roles", (
                mockInstance.attributeValues.contains("first role") &&
                mockInstance.attributeValues.contains("second role") &&
                mockInstance.attributeValues.contains("third role")));
    }

    public void testFindUserBravoConfiguredRoles() {
        mockInstance.findUser("bravo", "second", KEY);
        assertTrue("Bravo has proper roles", (
                !mockInstance.attributeValues.contains("first role") &&
                mockInstance.attributeValues.contains("second role") &&
                !mockInstance.attributeValues.contains("third role")));
    }

    public void testFindUserCharlieConfiguredRoles() {
        mockInstance.findUser("charlie", "third", KEY);
        assertTrue("Charlie has proper roles", (
                mockInstance.attributeValues.contains("authenticated user") &&
                !mockInstance.attributeValues.contains("first role") &&
                !mockInstance.attributeValues.contains("second role") &&
                !mockInstance.attributeValues.contains("third role")));
    }

    private class MockHandler implements CallbackHandler {
        public void handle(Callback[] callbacks) throws IOException,
        UnsupportedCallbackException {
            // No-op
        }
    }
}
