package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class IntruderXTab implements ITab {
    private final IBurpExtenderCallbacks callbacks;
    private final JPanel panel;
    private final JTabbedPane tabs;

    public IntruderXTab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.panel = new JPanel(new BorderLayout());
        this.tabs = new JTabbedPane();
        
        this.tabs.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int index = tabs.indexAtLocation(e.getX(), e.getY());
                    if (index != -1) {
                        String currentTitle = tabs.getTitleAt(index);
                        String newTitle = JOptionPane.showInputDialog(panel, "Rename tab:", currentTitle);
                        if (newTitle != null && !newTitle.trim().isEmpty()) {
                            tabs.setTitleAt(index, newTitle);
                        }
                    }
                }
            }
        });
        
        this.panel.add(tabs, BorderLayout.CENTER);
    }

    @Override
    public String getTabCaption() {
        return "burp-intruder";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

    public void addScanTab(byte[] request, IHttpService httpService) {
        SwingUtilities.invokeLater(() -> {
            ScanTab scanTab = new ScanTab(callbacks, request, httpService, tabs);
            int index = tabs.getTabCount();
            String title = "Scan " + (index + 1);
            if (httpService != null && httpService.getHost() != null) {
                title = httpService.getHost();
            }
            tabs.addTab(title, scanTab.getComponent());
            tabs.setSelectedIndex(index);
        });
    }
}
