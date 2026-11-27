package burp;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IntruderXTab mainTab;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("burp-intruder");

        SwingUtilities.invokeLater(() -> {
            mainTab = new IntruderXTab(callbacks);
            callbacks.addSuiteTab(mainTab);
            callbacks.registerContextMenuFactory(this);
            callbacks.printOutput("burp-intruder loaded successfully");
        });
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menu = new ArrayList<>();
        JMenuItem item = new JMenuItem("Send to burp-intruder");
        item.addActionListener(e -> {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            if (messages != null) {
                for (IHttpRequestResponse message : messages) {
                    mainTab.addScanTab(message.getRequest(), message.getHttpService());
                }
            }
        });
        menu.add(item);
        return menu;
    }
}
