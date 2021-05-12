package freenet.clients.http;

import com.mitchellbosecke.pebble.PebbleEngine;
import com.mitchellbosecke.pebble.extension.AbstractExtension;
import com.mitchellbosecke.pebble.extension.Function;
import com.mitchellbosecke.pebble.loader.ClasspathLoader;
import com.mitchellbosecke.pebble.loader.Loader;
import com.mitchellbosecke.pebble.template.EvaluationContext;
import com.mitchellbosecke.pebble.template.PebbleTemplate;
import freenet.client.HighLevelSimpleClient;
import freenet.l10n.NodeL10n;
import freenet.support.HTMLNode;

import java.io.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

abstract class WebTemplateToadlet extends Toadlet {

    private static final String TEMPLATE_ROOT_PATH = "freenet/clients/http/templates/";
    private static final String TEMPLATE_NAME_SUFFIX = ".html";

    private static final PebbleEngine templateEngine;

    static {
        Loader loader = new ClasspathLoader(WebTemplateToadlet.class.getClassLoader());
        loader.setPrefix(TEMPLATE_ROOT_PATH);
        loader.setSuffix(TEMPLATE_NAME_SUFFIX);

        templateEngine = new PebbleEngine.Builder().loader(loader).extension(new L10nExtension()).build();
    }

    WebTemplateToadlet(HighLevelSimpleClient client) {
        super(client);
    }

    /**
     * Add html from template to {@code parent} node.
     *
     * @param parent Parent html node.
     * @param templateName Html page name (without extension) that located in src/freenet/clients/http/templates.
     * @param model The map with all variables that template should use.
     * @throws IOException If the template cannot be read.
     */
    void addChild(HTMLNode parent, String templateName, Map<String, Object> model) throws IOException {
        addChild(parent, templateName, model, "");
    }

    void addChild(HTMLNode parent, String templateName, Map<String, Object> model, String l10nPrefix) throws IOException {
        model.put("l10nPrefix", l10nPrefix);
        PebbleTemplate template = templateEngine.getTemplate(templateName);

        Writer writer = new StringWriter();
        template.evaluate(writer, model);

        parent.addChild("%", writer.toString());
    }
}

class L10nExtension extends AbstractExtension {

    @Override
    public Map<String, Function> getFunctions() {
        Map<String, Function> functions = new HashMap<>();
        functions.put("l10n", new L10nFunction());
        return functions;
    }
}

class L10nFunction implements Function {

    @Override
    public Object execute(Map<String, Object> args, PebbleTemplate self, EvaluationContext context, int lineNumber) {
        Object key = args.get("0");
        if (key == null) {
            return "null";
        }
        return NodeL10n.getBase().getString(context.getVariable("l10nPrefix") + key.toString());
    }

    @Override
    public List<String> getArgumentNames() {
        return null;
    }
}
