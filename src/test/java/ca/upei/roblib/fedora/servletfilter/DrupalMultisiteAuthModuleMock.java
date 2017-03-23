package ca.upei.roblib.fedora.servletfilter;

import java.io.IOException;

import org.dom4j.Document;
import org.dom4j.DocumentException;

public class DrupalMultisiteAuthModuleMock extends DrupalMultisiteAuthModule {
    public DrupalMultisiteAuthModuleMock() throws IOException, DocumentException {
        super();
    }

    @Override
    protected void parseConfig() throws DocumentException, IOException {
        Document doc = getParsedConfig(this.getClass().getResourceAsStream("/filter-drupal-multisite.xml"));
        parseConfig(doc);
    }
}
