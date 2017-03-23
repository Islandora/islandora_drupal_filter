package ca.upei.roblib.fedora.servletfilter.jaas;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class MissingCredsException extends UnsupportedCallbackException {

    /**
     *
     */
    private static final long serialVersionUID = 5743041997336340500L;

    public MissingCredsException(Callback callback) {
        super(callback);
    }
}
