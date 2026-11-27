package burp;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.Toolkit;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ScanTab {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final byte[] initialRequest;
    private final IHttpService httpService;
    private final JTabbedPane parentTabs;
    private final JPanel panel;

    private JTextField endpointField;
    private JButton startBtn, stopBtn, pauseBtn;
    private IMessageEditor requestEditor;
    private JComboBox<String> attackModeCombo;
    private JComboBox<Integer> payloadPositionCombo;
    private JPanel payloadConfigArea;
    private List<JPanel> payloadPanels = new ArrayList<>();
    private List<DefaultTableModel> wordlistModels = new ArrayList<>();
    private List<TableRowSorter<DefaultTableModel>> wordlistSorters = new ArrayList<>();
    private List<JTextArea> customWordlistAreas = new ArrayList<>();

    private JLabel payloadCountLabel, requestCountLabel;
    private JTextField threadsField, reqPerConnField, retriesField, retryDelayField;
    private boolean pipelineEnabled = false;
    private JButton pipelineBtn;
    private String wordlistDir = System.getProperty("os.name", "").toLowerCase().contains("win")
            ? "C:\\Users\\Marcos\\Wordlists\\custom-wordlists"
            : "/media/rh4ps00dy/Data/Wordlists/Custom";

    private JTextField delayField;
    private JCheckBox encodeCheck;
    private JTextField encodeCharsField;
    
    private DefaultListModel<String> grepMatchListModel;
    private JList<String> grepMatchList;
    private JTextField grepExtractField;
    private List<String> currentMatchStrings = new ArrayList<>();
    private Pattern currentExtractPattern;
    
    private DefaultListModel<String> rulesListModel;
    private JList<String> rulesList;
    private JComboBox<String> rulesCombo;

    private JCheckBox rawModeCheck, chainCheck;
    private RequestEngine engine;
    private ResultsDisplay currentResults;

    private boolean lastFocusedTarget = false;
    private int currentMarkerPairs = 1;
    private boolean isPaused = false;


    public ScanTab(IBurpExtenderCallbacks callbacks, byte[] request, IHttpService httpService, JTabbedPane parentTabs) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.initialRequest = request;
        this.httpService = httpService;
        this.parentTabs = parentTabs;
        this.panel = new JPanel(new BorderLayout());

        initUi();
    }

    private void initUi() {
        JPanel topBar = new JPanel(new BorderLayout());
        topBar.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JPanel topBarLeft = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        String endpoint = "";
        if (httpService != null) {
            endpoint = httpService.getProtocol() + "://" + httpService.getHost() + ":" + httpService.getPort();
        }
        JLabel targetLabel = new JLabel("Target:");
        targetLabel.setFont(targetLabel.getFont().deriveFont(Font.BOLD));
        topBarLeft.add(targetLabel);
        
        endpointField = new JTextField(endpoint, 40);
        topBarLeft.add(endpointField);

        startBtn = new JButton("Start Attack");
        startBtn.setBackground(new Color(255, 102, 51));
        startBtn.setForeground(Color.WHITE);
        startBtn.setFocusPainted(false);
        startBtn.setFont(startBtn.getFont().deriveFont(Font.BOLD));
        startBtn.addActionListener(e -> startAttack());
        topBarLeft.add(startBtn);

        stopBtn = new JButton("Stop");
        stopBtn.setEnabled(false);
        stopBtn.setFocusPainted(false);
        stopBtn.addActionListener(e -> stopAttack());
        topBarLeft.add(stopBtn);

        pauseBtn = new JButton("Pause");
        pauseBtn.setEnabled(false);
        pauseBtn.setFocusPainted(false);
        pauseBtn.addActionListener(e -> togglePause());
        topBarLeft.add(pauseBtn);

        JButton closeBtn = new JButton("Close Tab");
        closeBtn.addActionListener(e -> closeTab());
        topBarLeft.add(closeBtn);
        topBar.add(topBarLeft, BorderLayout.WEST);

        // --- Request Editor (Left Side) ---
        JPanel editorPanel = new JPanel(new BorderLayout());
        JPanel markerBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        markerBar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
            BorderFactory.createEmptyBorder(5, 5, 10, 5)
        ));
        
        JButton addMarkerBtn = new JButton("Add \u00a7");
        addMarkerBtn.addActionListener(e -> addMarker());
        markerBar.add(addMarkerBtn);
        
        JButton clearMarkerBtn = new JButton("Clear \u00a7");
        clearMarkerBtn.addActionListener(e -> clearMarkers());
        markerBar.add(clearMarkerBtn);
        
        JButton syncBtn = new JButton("Sync Sets");
        syncBtn.addActionListener(e -> refreshPayloadSets());
        markerBar.add(syncBtn);

        JButton cleanBtn = new JButton("Clean Headers");
        cleanBtn.addActionListener(e -> cleanHeaders());
        markerBar.add(cleanBtn);
        
        editorPanel.add(markerBar, BorderLayout.NORTH);

        requestEditor = callbacks.createMessageEditor(null, true);
        if (initialRequest != null) {
            requestEditor.setMessage(initialRequest, true);
            cleanHeaders();
        }
        installGlobalFocusTracking();
        
        Component editorComponent = requestEditor.getComponent();
        enableWordWrap(editorComponent);
        editorPanel.add(editorComponent, BorderLayout.CENTER);

        // --- Settings Tabs (Right Side) ---
        JTabbedPane settingsTabs = new JTabbedPane();

        // 1. Payloads Tab
        JPanel payloadTab = new JPanel(new BorderLayout(5, 5));
        payloadTab.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JPanel modePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        modePanel.setBorder(BorderFactory.createTitledBorder("Attack Mode"));
        attackModeCombo = new JComboBox<>(new String[]{"Sniper", "Battering Ram", "Cluster Bomb"});
        attackModeCombo.addActionListener(e -> refreshPayloadSets());
        modePanel.add(attackModeCombo);
        payloadTab.add(modePanel, BorderLayout.NORTH);

        JPanel payloadWrapper = new JPanel(new BorderLayout());
        payloadWrapper.setBorder(BorderFactory.createTitledBorder("Payload Sets"));
        JPanel comboPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        comboPanel.add(new JLabel("Payload set:"));
        payloadPositionCombo = new JComboBox<>();
        payloadPositionCombo.addActionListener(e -> onPayloadPositionChanged());
        comboPanel.add(payloadPositionCombo);
        payloadWrapper.add(comboPanel, BorderLayout.NORTH);
        
        payloadConfigArea = new JPanel(new BorderLayout());
        payloadWrapper.add(payloadConfigArea, BorderLayout.CENTER);
        
        JPanel statsPanel = new JPanel(new GridLayout(2, 1));
        payloadCountLabel = new JLabel("Payload count: 0");
        requestCountLabel = new JLabel("Total Request count: 0");
        statsPanel.add(payloadCountLabel);
        statsPanel.add(requestCountLabel);
        payloadWrapper.add(statsPanel, BorderLayout.SOUTH);
        payloadTab.add(payloadWrapper, BorderLayout.CENTER);

        for (int i = 0; i < 20; i++) {
            createPayloadSetPanel(i);
        }
        refreshPayloadSets();

        // 2. Engine Tab
        JPanel engineTab = new JPanel(new GridBagLayout());
        engineTab.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints egbc = new GridBagConstraints();
        egbc.insets = new Insets(5, 5, 5, 5);
        egbc.anchor = GridBagConstraints.WEST;
        egbc.fill = GridBagConstraints.HORIZONTAL;

        egbc.gridx = 0; egbc.gridy = 0; engineTab.add(new JLabel("Threads:"), egbc);
        threadsField = new JTextField("5", 10);
        egbc.gridx = 1; engineTab.add(threadsField, egbc);

        egbc.gridx = 0; egbc.gridy = 1; engineTab.add(new JLabel("Reqs/Conn:"), egbc);
        reqPerConnField = new JTextField("100", 10);
        egbc.gridx = 1; engineTab.add(reqPerConnField, egbc);

        egbc.gridx = 0; egbc.gridy = 2; engineTab.add(new JLabel("Delay (ms):"), egbc);
        delayField = new JTextField("0", 10);
        egbc.gridx = 1; engineTab.add(delayField, egbc);

        rawModeCheck = new JCheckBox("Raw Mode (No normalization)", false);
        egbc.gridx = 0; egbc.gridy = 3; egbc.gridwidth = 2;
        engineTab.add(rawModeCheck, egbc);

        chainCheck = new JCheckBox("Chain wordlists (Sequential attacks)", false);
        egbc.gridy = 4;
        engineTab.add(chainCheck, egbc);

        pipelineBtn = new JButton("Pipeline: Off");
        egbc.gridy = 5;

        pipelineBtn.addActionListener(e -> {
            pipelineEnabled = !pipelineEnabled;
            pipelineBtn.setText("Pipeline: " + (pipelineEnabled ? "On" : "Off"));
        });
        egbc.gridx = 0; egbc.gridy = 5; egbc.gridwidth = 2;
        engineTab.add(pipelineBtn, egbc);

        // Error handling
        egbc.gridx = 0; egbc.gridy = 6; egbc.gridwidth = 2;
        egbc.insets = new Insets(15, 5, 2, 5);
        JLabel errorHandlingLabel = new JLabel("Error handling");
        errorHandlingLabel.setFont(errorHandlingLabel.getFont().deriveFont(Font.BOLD));
        engineTab.add(errorHandlingLabel, egbc);

        egbc.gridy = 7;
        egbc.insets = new Insets(2, 5, 10, 5);
        JLabel errorHandlingDesc = new JLabel("These settings control how Intruder handles network errors during the attack.");
        errorHandlingDesc.setFont(errorHandlingDesc.getFont().deriveFont(Font.PLAIN));
        engineTab.add(errorHandlingDesc, egbc);

        egbc.insets = new Insets(5, 5, 5, 5);
        egbc.gridwidth = 1;
        egbc.gridx = 0; egbc.gridy = 8;
        engineTab.add(new JLabel("Number of retries on network failure:"), egbc);
        retriesField = new JTextField("0", 10);
        egbc.gridx = 1;
        engineTab.add(retriesField, egbc);

        egbc.gridx = 0; egbc.gridy = 9;
        engineTab.add(new JLabel("Pause before retry (milliseconds):"), egbc);
        retryDelayField = new JTextField("2000", 10);
        egbc.gridx = 1;
        engineTab.add(retryDelayField, egbc);
        
        JPanel engineWrapper = new JPanel(new BorderLayout());
        engineWrapper.add(engineTab, BorderLayout.NORTH);

        // 3. Grep Tab
        JPanel grepTab = new JPanel(new GridBagLayout());
        grepTab.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints ggbc = new GridBagConstraints();
        ggbc.insets = new Insets(5, 5, 5, 5);
        ggbc.anchor = GridBagConstraints.WEST;
        ggbc.fill = GridBagConstraints.HORIZONTAL;
        ggbc.weightx = 1.0;

        // Title and Description
        JLabel grepTitleLabel = new JLabel("Grep - Match");
        grepTitleLabel.setFont(grepTitleLabel.getFont().deriveFont(Font.BOLD, 14f));
        ggbc.gridx = 0; ggbc.gridy = 0; ggbc.gridwidth = 2;
        grepTab.add(grepTitleLabel, ggbc);

        JLabel grepDescLabel = new JLabel("These settings can be used to flag result items containing specified expressions.");
        grepDescLabel.setFont(grepDescLabel.getFont().deriveFont(Font.PLAIN));
        ggbc.gridy = 1;
        grepTab.add(grepDescLabel, ggbc);

        // List Model and JList
        grepMatchListModel = new DefaultListModel<>();
        List<String> terms = new ArrayList<>();
        try (java.io.InputStream is = ScanTab.class.getResourceAsStream("/default_grep_terms.txt")) {
            if (is != null) {
                try (java.util.Scanner sc = new java.util.Scanner(is, "UTF-8")) {
                    while (sc.hasNextLine()) {
                        String line = sc.nextLine().trim();
                        if (!line.isEmpty()) {
                            terms.add(line);
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        if (terms.isEmpty()) {
            String[] defaultTerms = {
                "login", "log in", "signin", "sign in", "signup", "sign up", "register", "registration",
                "iniciar sesion", "iniciar sesión", "registrarse", "crear cuenta", "acceso",
                "inloggen", "aanmelden", "registreren", "einloggen", "anmelden", "registrieren",
                "connexion", "se connecter", "s'inscrire", "accedi", "accedere", "registrati",
                "type=\"password\"", "name=\"password\"", "id=\"password\"",
                "placeholder=\"*login*\"", "placeholder=\"*password*\"", "placeholder=\"*contrase*\"",
                "placeholder=\"*wachtwoord*\"", "placeholder=\"*passwort*\"",
                "value=\"*login*\"", "value=\"*sign*\"",
                ">*login*<", ">*sign*<",
                "profile", "perfil", "account", "cuenta", "dashboard", "panel", "my-account", "mi-cuenta",
                "user", "usuario", "settings", "configuracion", "configuración", "mon-compte", "mein-konto",
                "mijn-account", "profiel", "name=\"username\"", "id=\"username\"", "name=\"email\"", "id=\"email\"",
                "placeholder=\"*perfil*\"", "placeholder=\"*profile*\"", "placeholder=\"*usuario*\"", "placeholder=\"*username*\"",
                "value=\"*profile*\"", "value=\"*account*\"", ">perfil<", ">profile<", ">dashboard<", ">mi cuenta<", ">my account<"
            };
            for (String term : defaultTerms) {
                terms.add(term);
            }
        }
        for (String term : terms) {
            grepMatchListModel.addElement(term);
        }
        grepMatchList = new JList<>(grepMatchListModel);
        JScrollPane listScroll = new JScrollPane(grepMatchList);
        listScroll.setPreferredSize(new Dimension(300, 150));

        // Buttons Panel (Left of the list)
        JPanel listButtonsPanel = new JPanel(new GridLayout(4, 1, 5, 5));
        JButton pasteBtn = new JButton("Paste");
        JButton loadBtn = new JButton("Load...");
        JButton removeBtn = new JButton("Remove");
        JButton clearBtn = new JButton("Clear");

        pasteBtn.addActionListener(e -> pasteGrepMatchItems());
        loadBtn.addActionListener(e -> loadGrepMatchItems());
        removeBtn.addActionListener(e -> {
            int[] selectedIndices = grepMatchList.getSelectedIndices();
            for (int i = selectedIndices.length - 1; i >= 0; i--) {
                grepMatchListModel.remove(selectedIndices[i]);
            }
        });
        clearBtn.addActionListener(e -> grepMatchListModel.clear());

        listButtonsPanel.add(pasteBtn);
        listButtonsPanel.add(loadBtn);
        listButtonsPanel.add(removeBtn);
        listButtonsPanel.add(clearBtn);

        // Panel holding Buttons + List
        JPanel listAndButtonsPanel = new JPanel(new BorderLayout(10, 10));
        listAndButtonsPanel.add(listButtonsPanel, BorderLayout.WEST);
        listAndButtonsPanel.add(listScroll, BorderLayout.CENTER);

        ggbc.gridy = 2; ggbc.gridwidth = 2;
        ggbc.fill = GridBagConstraints.BOTH;
        ggbc.weighty = 0.5;
        grepTab.add(listAndButtonsPanel, ggbc);

        // Add Item Row
        JPanel addItemPanel = new JPanel(new BorderLayout(5, 5));
        JTextField newItemField = new JTextField();
        JButton addItemBtn = new JButton("Add");
        java.awt.event.ActionListener addAction = e -> {
            String text = newItemField.getText().trim();
            if (!text.isEmpty()) {
                grepMatchListModel.addElement(text);
                newItemField.setText("");
            }
        };
        addItemBtn.addActionListener(addAction);
        newItemField.addActionListener(addAction);
        addItemPanel.add(addItemBtn, BorderLayout.WEST);
        addItemPanel.add(newItemField, BorderLayout.CENTER);

        ggbc.gridy = 3; ggbc.fill = GridBagConstraints.HORIZONTAL; ggbc.weighty = 0.0;
        grepTab.add(addItemPanel, ggbc);

        // Separator
        JSeparator separator = new JSeparator(JSeparator.HORIZONTAL);
        ggbc.gridy = 4;
        grepTab.add(separator, ggbc);

        // Grep Extract Section
        JLabel extractLabel = new JLabel("Grep Extract (Regex):");
        extractLabel.setFont(extractLabel.getFont().deriveFont(Font.BOLD));
        ggbc.gridy = 5;
        grepTab.add(extractLabel, ggbc);

        grepExtractField = new JTextField("Location:\\s*(.*)", 20);
        ggbc.gridy = 6;
        grepTab.add(grepExtractField, ggbc);
        
        JPanel grepWrapper = new JPanel(new BorderLayout());
        grepWrapper.add(grepTab, BorderLayout.NORTH);

        // 4. Processing Tab
        JPanel procTab = new JPanel(new GridBagLayout());
        procTab.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints pgbc = new GridBagConstraints();
        pgbc.insets = new Insets(5, 5, 5, 5);
        pgbc.anchor = GridBagConstraints.WEST;

        encodeCheck = new JCheckBox("URL-encode:", false);
        encodeCharsField = new JTextField("^=<>?+&*:,;\"{}|^#", 15);
        JPanel encBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        encBox.add(encodeCheck);
        encBox.add(encodeCharsField);
        pgbc.gridx = 0; pgbc.gridy = 0; pgbc.gridwidth = 2;
        procTab.add(encBox, pgbc);

        JPanel procBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        procBox.add(new JLabel("Rules:"));
        rulesCombo = new JComboBox<>(new String[]{"MD5", "SHA-1", "SHA-256", "Base64 Encode", "Hex Encode", "Add Prefix", "Add Suffix", "Upper Case", "Lower Case"});
        procBox.add(rulesCombo);
        JButton addRuleBtn = new JButton("Add");
        addRuleBtn.addActionListener(e -> addRule());
        procBox.add(addRuleBtn);
        JButton clearRulesBtn = new JButton("Clear");
        clearRulesBtn.addActionListener(e -> rulesListModel.clear());
        procBox.add(clearRulesBtn);
        pgbc.gridy = 1;
        procTab.add(procBox, pgbc);

        rulesListModel = new DefaultListModel<>();
        rulesList = new JList<>(rulesListModel);
        JScrollPane rulesScroll = new JScrollPane(rulesList);
        rulesScroll.setPreferredSize(new Dimension(250, 100));
        pgbc.gridx = 0; pgbc.gridy = 2; pgbc.gridwidth = 2; pgbc.fill = GridBagConstraints.BOTH; pgbc.weightx = 1.0; pgbc.weighty = 1.0;
        procTab.add(rulesScroll, pgbc);

        settingsTabs.addTab("Payloads", payloadTab);
        settingsTabs.addTab("Engine", engineWrapper);
        settingsTabs.addTab("Grep", grepWrapper);
        settingsTabs.addTab("Processing", procTab);

        // --- Assembly ---
        JSplitPane configSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, editorPanel, settingsTabs);
        configSplit.setResizeWeight(0.75);
        configSplit.setDividerLocation(0.75);

        panel.setLayout(new BorderLayout());
        panel.add(topBar, BorderLayout.NORTH);
        panel.add(configSplit, BorderLayout.CENTER);
        
        refreshWordlistTables();
    }




    private void enableWordWrap(Component comp) {
        if (comp instanceof JTextArea) {
            ((JTextArea) comp).setLineWrap(true);
            ((JTextArea) comp).setWrapStyleWord(true);
        } else if (comp instanceof Container) {
            for (Component child : ((Container) comp).getComponents()) {
                enableWordWrap(child);
            }
        }
    }

    private JTextArea findTextArea(Component comp) {
        if (comp instanceof JTextArea) return (JTextArea) comp;
        if (comp instanceof Container) {
            for (Component child : ((Container) comp).getComponents()) {
                JTextArea ta = findTextArea(child);
                if (ta != null) return ta;
            }
        }
        return null;
    }

    private void addMarker() {
        if (shouldApplyMarkersToTarget()) {
            addMarkerToTextComponent(endpointField);
            refreshPayloadSets();
            return;
        }

        JTextArea ta = findTextArea(requestEditor.getComponent());
        if (ta != null) {
            addMarkerToTextComponent(ta);
            requestEditor.setMessage(helpers.stringToBytes(ta.getText()), true);
            refreshPayloadSets();
        } else {
            byte[] textBytes = requestEditor.getMessage();
            String text = helpers.bytesToString(textBytes);
            requestEditor.setMessage(helpers.stringToBytes(text + "\u00a7\u00a7"), true);
            refreshPayloadSets();
        }
    }

    private void cleanHeaders() {
        byte[] textBytes = requestEditor.getMessage();
        if (textBytes == null) return;
        String text = helpers.bytesToString(textBytes);
        int headerEnd = text.indexOf("\r\n\r\n");
        if (headerEnd == -1) headerEnd = text.indexOf("\n\n");
        if (headerEnd == -1) return;

        String headerSection = text.substring(0, headerEnd);
        String body = text.substring(headerEnd);
        
        String[] lines = headerSection.split("\\r?\\n");
        if (lines.length == 0) return;

        StringBuilder sb = new StringBuilder();
        
        // 1. Process Request Line (Downgrade HTTP/2 if present)
        String firstLine = lines[0];
        if (firstLine.contains("HTTP/2")) {
            firstLine = firstLine.replace("HTTP/2", "HTTP/1.1");
        }
        sb.append(firstLine).append("\r\n");

        boolean hostPresent = false;
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            String lineLower = line.toLowerCase();

            // 2. Handle Pseudo-headers and Authority -> Host conversion
            if (lineLower.startsWith(":authority:")) {
                if (!hostPresent) {
                    sb.append("Host: ").append(line.substring(11).trim()).append("\r\n");
                    hostPresent = true;
                }
                continue;
            }
            if (lineLower.startsWith(":")) {
                continue;
            }

            if (lineLower.startsWith("host:")) {
                hostPresent = true;
            }

            sb.append(line).append("\r\n");
        }

        
        requestEditor.setMessage(helpers.stringToBytes(sb.toString() + body), true);
    }

    private void clearMarkers() {
        if (shouldApplyMarkersToTarget()) {
            endpointField.setText(endpointField.getText().replace("\u00a7", ""));
            refreshPayloadSets();
            return;
        }

        byte[] textBytes = requestEditor.getMessage();
        String text = helpers.bytesToString(textBytes);
        requestEditor.setMessage(helpers.stringToBytes(text.replace("\u00a7", "")), true);
        refreshPayloadSets();
    }

    private void addMarkerToTextComponent(JTextComponent tc) {
        int s = tc.getSelectionStart();
        int e = tc.getSelectionEnd();
        String text = tc.getText();
        String marker = "\u00a7";
        String newText;

        if (s != e && s >= 0 && e <= text.length()) {
            newText = text.substring(0, s) + marker + text.substring(s, e) + marker + text.substring(e);
        } else if (s >= 0 && s <= text.length()) {
            newText = text.substring(0, s) + marker + marker + text.substring(s);
        } else {
            newText = text + marker + marker;
        }

        tc.setText(newText);
    }

    private boolean shouldApplyMarkersToTarget() {
        Component focused = KeyboardFocusManager.getCurrentKeyboardFocusManager().getPermanentFocusOwner();

        if (isDescendantOf(focused, endpointField)) {
            lastFocusedTarget = true;
            return true;
        }

        if (isDescendantOf(focused, requestEditor.getComponent())) {
            lastFocusedTarget = false;
            return false;
        }

        return lastFocusedTarget;
    }

    private void installGlobalFocusTracking() {
        KeyboardFocusManager.getCurrentKeyboardFocusManager().addPropertyChangeListener("permanentFocusOwner", evt -> {
            Object value = evt.getNewValue();
            if (!(value instanceof Component)) return;
            Component focused = (Component) value;

            if (isDescendantOf(focused, endpointField)) {
                lastFocusedTarget = true;
            } else if (isDescendantOf(focused, requestEditor.getComponent())) {
                lastFocusedTarget = false;
            }
        });
    }

    private boolean isDescendantOf(Component child, Component parent) {
        return child != null && parent != null && (child == parent || SwingUtilities.isDescendingFrom(child, parent));
    }

    private JPanel createPayloadSetPanel(int index) {
        JPanel p = new JPanel(new BorderLayout());
        JTabbedPane tabs = new JTabbedPane();
        
        JPanel explorerPanel = new JPanel(new BorderLayout(5, 5));
        
        // Search bar
        JTextField searchField = new JTextField();
        searchField.setToolTipText("Search wordlists...");
        explorerPanel.add(searchField, BorderLayout.NORTH);

        // Table with Checkboxes
        DefaultTableModel model = new DefaultTableModel(new Object[]{"", "Wordlist"}, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };
        wordlistModels.add(model);
        
        JTable table = new JTable(model);
        table.getColumnModel().getColumn(0).setMaxWidth(30);
        table.setTableHeader(null); // Clean look
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 0));
        
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        wordlistSorters.add(sorter);

        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            private void filter() {
                String text = searchField.getText();
                if (text.trim().length() == 0) sorter.setRowFilter(null);
                else sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(text), 1));
            }
        });

        explorerPanel.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel listBtns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.addActionListener(e -> refreshWordlistTables());
        JButton setDirBtn = new JButton("Set Dir");
        setDirBtn.addActionListener(e -> pickDir());
        
        listBtns.add(setDirBtn);
        listBtns.add(refreshBtn);
        explorerPanel.add(listBtns, BorderLayout.SOUTH);
        
        tabs.addTab("Files", explorerPanel);
        
        JTextArea area = new JTextArea(8, 25);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        customWordlistAreas.add(area);
        tabs.addTab("Paste", new JScrollPane(area));
        
        p.add(tabs, BorderLayout.CENTER);
        payloadPanels.add(p);
        
        // Update stats when checkboxes change
        model.addTableModelListener(e -> updateStats());

        area.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateStats(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateStats(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateStats(); }
        });
        
        return p;
    }

    private void onPayloadPositionChanged() {
        Integer selected = (Integer) payloadPositionCombo.getSelectedItem();
        if (selected != null) {
            payloadConfigArea.removeAll();
            payloadConfigArea.add(payloadPanels.get(selected - 1), BorderLayout.CENTER);
            payloadConfigArea.revalidate();
            payloadConfigArea.repaint();
            updateStats();
        }
    }

    private void refreshPayloadSets() {
        if (payloadPositionCombo == null) return;
        
        String mode = (String) attackModeCombo.getSelectedItem();
        int required;
        if (mode.equals("Cluster Bomb")) {
            required = countMarkerPairs();
            if (required == 0) required = 1;
        } else {
            required = 1;
        }
        
        int current = payloadPositionCombo.getItemCount();
        if (current != required) {
            Object currentSel = payloadPositionCombo.getSelectedItem();
            payloadPositionCombo.removeAllItems();
            for (int i = 1; i <= required && i <= 20; i++) {
                payloadPositionCombo.addItem(i);
            }
            if (currentSel != null && (Integer) currentSel <= required) {
                payloadPositionCombo.setSelectedItem(currentSel);
            } else {
                payloadPositionCombo.setSelectedIndex(0);
            }
        }
        // Always refresh the displayed panel to keep it in sync
        onPayloadPositionChanged();
        updateStats();
    }

    private void updateStats() {
        if (payloadCountLabel == null) return;
        
        String mode = (String) attackModeCombo.getSelectedItem();
        int required = mode.equals("Cluster Bomb") ? countMarkerPairs() : 1;
        if (required == 0) required = 1;

        int activeCount = getWordCount(payloadPositionCombo.getSelectedIndex());
        long totalRequests;
        
        if (mode.equals("Cluster Bomb")) {
            totalRequests = 1;
            for (int i = 0; i < required; i++) {
                int count = getWordCount(i);
                totalRequests *= Math.max(1, count);
            }
        } else if (mode.equals("Sniper")) {
            totalRequests = (long) getWordCount(0) * required;
        } else { // Battering Ram
            totalRequests = getWordCount(0);
        }
        
        payloadCountLabel.setText("Payload count: " + activeCount);
        requestCountLabel.setText("Total Request count: " + totalRequests);
    }

    private int getWordCount(int index) {
        if (index < 0 || index >= payloadPanels.size()) return 0;
        JTabbedPane tabs = (JTabbedPane) payloadPanels.get(index).getComponent(0);
        int total = 0;
        if (tabs.getSelectedIndex() == 0) {
            DefaultTableModel model = wordlistModels.get(index);
            for (int i = 0; i < model.getRowCount(); i++) {
                if ((Boolean) model.getValueAt(i, 0)) {
                    String filename = (String) model.getValueAt(i, 1);
                    try (java.util.Scanner sc = new java.util.Scanner(new File(wordlistDir, filename))) {
                        while (sc.hasNextLine()) { sc.nextLine(); total++; }
                    } catch (Exception ignored) {}
                }
            }
        } else {
            String text = customWordlistAreas.get(index).getText().trim();
            if (!text.isEmpty()) {
                total = (int) java.util.Arrays.stream(text.split("\n")).filter(l -> !l.trim().isEmpty()).count();
            }
        }
        return total;
    }


    private int countMarkerPairs() {
        String url = endpointField.getText();
        String req = helpers.bytesToString(requestEditor.getMessage());
        int count = 0;
        for (char c : url.toCharArray()) if (c == '§') count++;
        for (char c : req.toCharArray()) if (c == '§') count++;
        return count / 2;
    }

    private void pickDir() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (new File(wordlistDir).exists()) chooser.setCurrentDirectory(new File(wordlistDir));
        if (chooser.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
            wordlistDir = chooser.getSelectedFile().getAbsolutePath();
            refreshWordlistTables();
        }

    }

    private void refreshWordlistTables() {
        File dir = new File(wordlistDir);
        String[] files = dir.exists() ? dir.list((d, name) -> new File(d, name).isFile()) : new String[0];
        if (files == null) files = new String[0];
        java.util.Arrays.sort(files, String.CASE_INSENSITIVE_ORDER);

        for (DefaultTableModel model : wordlistModels) {
            // Preserve selection if possible
            java.util.Set<String> selected = new java.util.HashSet<>();
            for (int i = 0; i < model.getRowCount(); i++) {
                if ((Boolean) model.getValueAt(i, 0)) selected.add((String) model.getValueAt(i, 1));
            }

            model.setRowCount(0);
            for (String f : files) {
                model.addRow(new Object[]{selected.contains(f), f});
            }
        }
        updateStats();
    }


    private void startAttack() {
        if (wordlistModels.get(0).getRowCount() == 0) {
            refreshWordlistTables(); // Lazy load if empty
        }
        if (chainCheck.isSelected()) {
            startChainedAttacks();
        } else {
            startCombinedAttack();
        }
    }

    private void startCombinedAttack() {
        List<List<RequestEngine.PayloadInfo>> allPayloads = new ArrayList<>();
        String mode = (String) attackModeCombo.getSelectedItem();
        int maxSets = mode.equals("Cluster Bomb") ? countMarkerPairs() : 1;
        if (maxSets == 0) maxSets = 1;
        currentMarkerPairs = Math.max(1, countMarkerPairs());

        for (int i = 0; i < maxSets; i++) {
            List<RequestEngine.PayloadInfo> currentSet = new ArrayList<>();
            JPanel pSet = payloadPanels.get(i);
            JTabbedPane tabs = (JTabbedPane) pSet.getComponent(0);
            if (tabs.getSelectedIndex() == 0) {
                DefaultTableModel model = wordlistModels.get(i);
                for (int j = 0; j < model.getRowCount(); j++) {
                    if ((Boolean) model.getValueAt(j, 0)) {
                        String filename = (String) model.getValueAt(j, 1);
                        try (java.util.Scanner scanner = new java.util.Scanner(new File(wordlistDir, filename))) {
                            while (scanner.hasNextLine()) {
                                currentSet.add(new RequestEngine.PayloadInfo(scanner.nextLine().trim(), filename));
                            }
                        } catch (Exception e) {
                            callbacks.printError("Error reading wordlist " + filename + ": " + e.getMessage());
                        }
                    }
                }
            } else {
                String content = customWordlistAreas.get(i).getText().trim();
                for (String line : content.split("\n")) {
                    if (!line.trim().isEmpty()) currentSet.add(new RequestEngine.PayloadInfo(line.trim(), "Custom List"));
                }
            }
            if (!currentSet.isEmpty()) allPayloads.add(currentSet);
        }

        if (allPayloads.isEmpty()) {
            JOptionPane.showMessageDialog(panel, "At least one wordlist must be configured!", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        executeAttack(allPayloads, mode);
    }

    private void startChainedAttacks() {
        DefaultTableModel model = wordlistModels.get(0);
        boolean hasSelected = false;
        for (int i = 0; i < model.getRowCount(); i++) if ((Boolean) model.getValueAt(i, 0)) hasSelected = true;

        if (!hasSelected) {
            startCombinedAttack(); // Fallback to whatever is configured
            return;
        }

        new Thread(() -> {
            for (int i = 0; i < model.getRowCount(); i++) {
                if (!(Boolean) model.getValueAt(i, 0)) continue;

                String filename = (String) model.getValueAt(i, 1);
                List<RequestEngine.PayloadInfo> set = new ArrayList<>();
                try (java.util.Scanner sc = new java.util.Scanner(new File(wordlistDir, filename))) {
                    while (sc.hasNextLine()) set.add(new RequestEngine.PayloadInfo(sc.nextLine().trim(), filename));
                } catch (Exception e) { continue; }
                
                if (set.isEmpty()) continue;
                
                List<List<RequestEngine.PayloadInfo>> payloads = new ArrayList<>();
                payloads.add(set);
                
                final Object lock = new Object();
                SwingUtilities.invokeLater(() -> {
                    executeAttack(payloads, (String) attackModeCombo.getSelectedItem());
                });

                // Wait for engine to finish
                while (engine != null && engine.isRunning()) {
                    try { Thread.sleep(500); } catch (InterruptedException e) { break; }
                }
            }
        }).start();
    }

    private void executeAttack(List<List<RequestEngine.PayloadInfo>> allPayloads, String mode) {
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        pauseBtn.setEnabled(true);
        pauseBtn.setText("Pause");
        isPaused = false;
        
        currentMatchStrings.clear();
        for (int i = 0; i < grepMatchListModel.size(); i++) {
            currentMatchStrings.add(grepMatchListModel.getElementAt(i).trim());
        }
        
        currentExtractPattern = null;
        String extractText = grepExtractField.getText().trim();
        if (!extractText.isEmpty()) {
            try { currentExtractPattern = Pattern.compile(extractText); } catch (Exception e) { callbacks.printError("Invalid Regex: " + e.getMessage()); }
        }
        
        List<String> columns = new ArrayList<>();
        columns.add("Request");
        if (currentMarkerPairs > 1) {
            for (int i = 1; i <= currentMarkerPairs; i++) columns.add("Payload " + i);
        } else {
            columns.add("Payload");
        }
        columns.add("Status code");
        columns.add("Response received");
        columns.add("Error");
        columns.add("Timeout");
        columns.add("Length");
        columns.add("Wordlist");
        columns.add("Match");
        if (currentExtractPattern != null) columns.add("Extracted");
        
        int delay = 0;
        try { delay = Integer.parseInt(delayField.getText().trim()); } catch (Exception ignored) {}
        int maxRetries = 3;
        try { maxRetries = Integer.parseInt(retriesField.getText().trim()); } catch (Exception ignored) {}
        int retryDelay = 2000;
        try { retryDelay = Integer.parseInt(retryDelayField.getText().trim()); } catch (Exception ignored) {}
        
        List<String[]> payloadRules = new ArrayList<>();
        for (int i = 0; i < rulesListModel.size(); i++) {
            String ruleStr = rulesListModel.getElementAt(i);
            if (ruleStr.contains(":")) {
                String type = ruleStr.substring(0, ruleStr.indexOf(":")).trim();
                String arg = ruleStr.substring(ruleStr.indexOf(":") + 1).trim();
                payloadRules.add(new String[]{type, arg});
            } else {
                payloadRules.add(new String[]{ruleStr, ""});
            }
        }

        currentResults = new ResultsDisplay(callbacks, httpService, this, new ArrayList<>(currentMatchStrings), currentExtractPattern, currentMarkerPairs, columns.toArray(new String[0]));
        
        engine = new RequestEngine(endpointField.getText(), requestEditor.getMessage(), allPayloads, mode,
                Integer.parseInt(threadsField.getText().trim()), Integer.parseInt(reqPerConnField.getText().trim()), 
                pipelineEnabled, delay, encodeCheck.isSelected(), encodeCharsField.getText(), currentResults::addResult, this::onFinished, payloadRules, rawModeCheck.isSelected(),
                maxRetries, retryDelay);
        engine.start();
    }



    private void addRule() {
        String selected = (String) rulesCombo.getSelectedItem();
        if (selected.equals("Add Prefix") || selected.equals("Add Suffix")) {
            String val = JOptionPane.showInputDialog(panel, "Enter value for " + selected + ":");
            if (val != null) rulesListModel.addElement(selected + ": " + val);
        } else {
            rulesListModel.addElement(selected);
        }
    }

    private void pasteGrepMatchItems() {
        try {
            String data = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
            if (data != null) {
                for (String line : data.split("\\r?\\n")) {
                    if (!line.trim().isEmpty()) {
                        grepMatchListModel.addElement(line.trim());
                    }
                }
            }
        } catch (Exception ignored) {}
    }

    private void loadGrepMatchItems() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try (java.util.Scanner sc = new java.util.Scanner(file)) {
                while (sc.hasNextLine()) {
                    String line = sc.nextLine().trim();
                    if (!line.isEmpty()) {
                        grepMatchListModel.addElement(line);
                    }
                }
            } catch (Exception ignored) {}
        }
    }

    public void stopAttack() {
        if (engine != null) engine.stop();
        onFinished();
    }


    private void onFinished() {
        SwingUtilities.invokeLater(() -> {
            startBtn.setEnabled(true);
            stopBtn.setEnabled(false);
            pauseBtn.setEnabled(false);
            pauseBtn.setText("Pause");
            if (currentResults != null) currentResults.onFinished();
        });
    }


    public void togglePause() {
        if (engine == null) return;
        isPaused = !isPaused;
        if (isPaused) {
            engine.pause();
            pauseBtn.setText("Resume");
        } else {
            engine.resume();
            pauseBtn.setText("Pause");
        }
        if (currentResults != null) currentResults.setPauseState(isPaused);
    }




    private void closeTab() {
        int idx = parentTabs.indexOfComponent(panel);
        if (idx != -1) {
            parentTabs.remove(idx);
            if (engine != null) engine.stop();
        }
    }


    public JPanel getComponent() { return panel; }
}
