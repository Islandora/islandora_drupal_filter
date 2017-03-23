package ca.upei.roblib.fedora.servletfilter.jaas;

import javax.security.auth.callback.ChoiceCallback;

public class KeyChoiceCallback extends ChoiceCallback {
    /**
     *
     */
    private static final long serialVersionUID = 891651588738513867L;

    public KeyChoiceCallback(String[] choices) {
        super("user_agent", choices, 0, false);
    }

    public int lookupKey(String value) {
        String[] choices = getChoices();
        for (int i = 0; i < choices.length; i++) {
            if (choices[i].equals(value)) {
                return i;
            }
        }
        throw new IllegalArgumentException(String.format("Invalid value for lookup: %s", value));
    }
}
