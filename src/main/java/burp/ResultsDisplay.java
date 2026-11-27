package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ResultsDisplay {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final IHttpService httpService;
    private final ScanTab parent;
    
    private JFrame frame;
    private DefaultTableModel tableModel;
    private JTable table;
    private TableRowSorter<DefaultTableModel> tableSorter;
    private final Map<Integer, byte[][]> resultsData = new HashMap<>();
    private IMessageEditor requestViewer, responseViewer;
    private JLabel statusLabel;
    
    private JTextField searchFilterField, hideLengthField;
    private JCheckBox regexFilterCheck, caseFilterCheck, negativeFilterCheck;
    private JCheckBox filter2xx, filter3xx, filter4xx, filter5xx;
    private JButton resultsStopBtn, resultsPauseBtn;

    private List<String> currentMatchStrings = new ArrayList<>();
    private Pattern currentExtractPattern;
    private int currentMarkerPairs;

    public ResultsDisplay(IBurpExtenderCallbacks callbacks, IHttpService httpService, ScanTab parent, 
                          List<String> matchStrings, Pattern extractPattern, int markerPairs, String[] columns) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.httpService = httpService;
        this.parent = parent;
        this.currentMatchStrings = matchStrings;
        this.currentExtractPattern = extractPattern;
        this.currentMarkerPairs = markerPairs;

        initUi(columns);
    }

    private void initUi(String[] columns) {
        String title = "burp-intruder Results";
        if (httpService != null && httpService.getHost() != null) {
            title += " - " + httpService.getHost();
        }
        frame = new JFrame(title);
        
        JPanel resultsPanel = new JPanel(new BorderLayout());
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                String colName = getColumnName(columnIndex);
                if ("Request".equals(colName) || "Status code".equals(colName) || "Response received".equals(colName) || "Length".equals(colName)) {
                    return Integer.class;
                }
                return String.class;
            }
        };
        table = new JTable(tableModel);
        tableSorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(tableSorter);
        table.getSelectionModel().addListSelectionListener(e -> onRowSelected());

        // Right-click context menu to send items to the Site Map
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showPopup(e);
                }
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showPopup(e);
                }
            }

            private void showPopup(java.awt.event.MouseEvent e) {
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0 && row < table.getRowCount()) {
                    if (!table.isRowSelected(row)) {
                        table.setRowSelectionInterval(row, row);
                    }
                } else {
                    table.clearSelection();
                }

                int[] selectedRows = table.getSelectedRows();
                if (selectedRows.length == 0) return;

                JPopupMenu popup = new JPopupMenu();
                JMenuItem sendToSitemapItem = new JMenuItem("Send to Site Map");
                sendToSitemapItem.addActionListener(evt -> {
                    for (int r : selectedRows) {
                        int modelRow = table.convertRowIndexToModel(r);
                        int id = (int) tableModel.getValueAt(modelRow, 0);
                        byte[][] data = resultsData.get(id);
                        if (data != null) {
                            IHttpRequestResponse reqRes = new IHttpRequestResponse() {
                                private byte[] request = data[0];
                                private byte[] response = data[1];
                                private String comment;
                                private String highlight;
                                private IHttpService service = httpService;

                                @Override
                                public byte[] getRequest() { return request; }

                                @Override
                                public void setRequest(byte[] message) { this.request = message; }

                                @Override
                                public byte[] getResponse() { return response; }

                                @Override
                                public void setResponse(byte[] message) { this.response = message; }

                                @Override
                                public String getComment() { return comment; }

                                @Override
                                public void setComment(String comment) { this.comment = comment; }

                                @Override
                                public String getHighlight() { return highlight; }

                                @Override
                                public void setHighlight(String highlight) { this.highlight = highlight; }

                                @Override
                                public IHttpService getHttpService() { return service; }

                                @Override
                                public void setHttpService(IHttpService httpService) { this.service = httpService; }
                            };
                            callbacks.addToSiteMap(reqRes);
                        }
                    }
                });
                popup.add(sendToSitemapItem);

                JMenuItem sendToRepeaterItem = new JMenuItem("Send to Repeater");
                sendToRepeaterItem.addActionListener(evt -> {
                    for (int r : selectedRows) {
                        int modelRow = table.convertRowIndexToModel(r);
                        int id = (int) tableModel.getValueAt(modelRow, 0);
                        byte[][] data = resultsData.get(id);
                        if (data != null && httpService != null) {
                            String host = httpService.getHost();
                            int port = httpService.getPort();
                            boolean useHttps = "https".equalsIgnoreCase(httpService.getProtocol());
                            byte[] request = data[0];
                            String tabTitle = "IX - " + id;
                            callbacks.sendToRepeater(host, port, useHttps, request, tabTitle);
                        }
                    }
                });
                popup.add(sendToRepeaterItem);

                popup.show(e.getComponent(), e.getX(), e.getY());
            }
        });

        // Column widths
        javax.swing.table.TableColumnModel colModel = table.getColumnModel();
        for (int i = 0; i < colModel.getColumnCount(); i++) {
            String colName = table.getColumnName(i);
            if ("Request".equals(colName)) {
                colModel.getColumn(i).setPreferredWidth(60);
                colModel.getColumn(i).setMaxWidth(80);
            } else if (colName.startsWith("Payload")) {
                colModel.getColumn(i).setPreferredWidth(250);
            } else if ("Status code".equals(colName)) {
                colModel.getColumn(i).setPreferredWidth(80);
                colModel.getColumn(i).setMaxWidth(100);
            } else if ("Response received".equals(colName)) {
                colModel.getColumn(i).setPreferredWidth(125);
                colModel.getColumn(i).setMaxWidth(150);
            } else if ("Error".equals(colName)) {
                colModel.getColumn(i).setPreferredWidth(200);
            } else if ("Timeout".equals(colName)) {
                colModel.getColumn(i).setPreferredWidth(70);
                colModel.getColumn(i).setMaxWidth(90);
            } else if ("Length".equals(colName)) {
                colModel.getColumn(i).setPreferredWidth(85);
                colModel.getColumn(i).setMaxWidth(110);
            } else if ("Wordlist".equals(colName)) {
                colModel.getColumn(i).setPreferredWidth(100);
            } else if ("Match".equals(colName)) {
                colModel.getColumn(i).setPreferredWidth(120);
            } else if ("Extracted".equals(colName)) {
                colModel.getColumn(i).setPreferredWidth(150);
            }
        }

        JPanel buttonBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        resultsStopBtn = new JButton("Stop Attack");
        resultsStopBtn.setBackground(new Color(255, 102, 51));
        resultsStopBtn.setForeground(Color.WHITE);
        resultsStopBtn.addActionListener(e -> parent.stopAttack());
        buttonBar.add(resultsStopBtn);

        resultsPauseBtn = new JButton("Pause");
        resultsPauseBtn.addActionListener(e -> parent.togglePause());
        buttonBar.add(resultsPauseBtn);

        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        JPanel searchSection = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        searchSection.add(new JLabel("Search:"));
        searchFilterField = new JTextField(20);
        searchSection.add(searchFilterField);
        regexFilterCheck = new JCheckBox("Regex");
        caseFilterCheck = new JCheckBox("Case sensitive");
        negativeFilterCheck = new JCheckBox("Negative search");
        searchSection.add(regexFilterCheck);
        searchSection.add(caseFilterCheck);
        searchSection.add(negativeFilterCheck);
        filterBar.add(searchSection);

        JPanel statusSection = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        statusSection.add(new JLabel("Status:"));
        filter2xx = new JCheckBox("2xx", true);
        filter3xx = new JCheckBox("3xx", true);
        filter4xx = new JCheckBox("4xx", true);
        filter5xx = new JCheckBox("5xx", true);
        statusSection.add(filter2xx);
        statusSection.add(filter3xx);
        statusSection.add(filter4xx);
        statusSection.add(filter5xx);
        filterBar.add(statusSection);

        hideLengthField = new JTextField(10);
        filterBar.add(new JLabel("Hide Length:"));
        filterBar.add(hideLengthField);

        java.awt.event.ActionListener filterAction = e -> applyFilters();
        regexFilterCheck.addActionListener(filterAction);
        caseFilterCheck.addActionListener(filterAction);
        negativeFilterCheck.addActionListener(filterAction);
        filter2xx.addActionListener(filterAction);
        filter3xx.addActionListener(filterAction);
        filter4xx.addActionListener(filterAction);
        filter5xx.addActionListener(filterAction);
        searchFilterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
        });
        hideLengthField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
        });

        JPanel tableHeaderPanel = new JPanel();
        tableHeaderPanel.setLayout(new BoxLayout(tableHeaderPanel, BoxLayout.Y_AXIS));
        tableHeaderPanel.add(buttonBar);
        tableHeaderPanel.add(new JSeparator(JSeparator.HORIZONTAL));
        tableHeaderPanel.add(filterBar);
        tableHeaderPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        IMessageEditorController controller = new IMessageEditorController() {
            public IHttpService getHttpService() { return httpService; }
            public byte[] getRequest() { return requestViewer.getMessage(); }
            public byte[] getResponse() { return responseViewer.getMessage(); }
        };
        requestViewer = callbacks.createMessageEditor(controller, false);
        responseViewer = callbacks.createMessageEditor(controller, false);
        JSplitPane viewerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer.getComponent(), responseViewer.getComponent());
        viewerSplit.setResizeWeight(0.5);

        JPanel tableContainer = new JPanel(new BorderLayout());
        tableContainer.add(tableHeaderPanel, BorderLayout.NORTH);
        tableContainer.add(new JScrollPane(table), BorderLayout.CENTER);

        JSplitPane resSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableContainer, viewerSplit);
        resSplit.setResizeWeight(0.5);
        resultsPanel.add(resSplit, BorderLayout.CENTER);

        statusLabel = new JLabel("Status: Running | Sent: 0");
        resultsPanel.add(statusLabel, BorderLayout.SOUTH);

        frame.add(resultsPanel);
        frame.setExtendedState(JFrame.MAXIMIZED_BOTH);
        callbacks.customizeUiComponent(frame);
        frame.setVisible(true);
        
        SwingUtilities.invokeLater(() -> resSplit.setDividerLocation(0.5));
    }

    private void onRowSelected() {
        int row = table.getSelectedRow();
        if (row != -1) {
            int modelRow = table.convertRowIndexToModel(row);
            int id = (int) tableModel.getValueAt(modelRow, 0);
            byte[][] data = resultsData.get(id);
            if (data != null) {
                requestViewer.setMessage(data[0], true);
                responseViewer.setMessage(data[1], false);
            }
        }
    }

    private void applyFilters() {
        RowFilter<DefaultTableModel, Integer> filter = new RowFilter<DefaultTableModel, Integer>() {
            @Override
            public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                int statusIdx = tableModel.findColumn("Status code");
                int status = 0;
                if (statusIdx >= 0) {
                    Object statusObj = entry.getValue(statusIdx);
                    if (statusObj instanceof Integer) status = (Integer) statusObj;
                }
                
                if (status >= 200 && status < 300 && !filter2xx.isSelected()) return false;
                if (status >= 300 && status < 400 && !filter3xx.isSelected()) return false;
                if (status >= 400 && status < 500 && !filter4xx.isSelected()) return false;
                if (status >= 500 && status < 600 && !filter5xx.isSelected()) return false;

                String term = searchFilterField.getText();
                if (term != null && !term.isEmpty()) {
                    int id = (Integer) entry.getValue(0);
                    byte[][] data = resultsData.get(id);
                    String textToSearch = "";
                    if (data != null && data.length > 1 && data[1] != null) {
                        textToSearch = helpers.bytesToString(data[1]);
                    }
                    boolean match = false;
                    if (regexFilterCheck.isSelected()) {
                        try {
                            Pattern p = caseFilterCheck.isSelected() ? Pattern.compile(term) : Pattern.compile(term, Pattern.CASE_INSENSITIVE);
                            match = p.matcher(textToSearch).find();
                        } catch (Exception e) { match = false; }
                    } else {
                        if (caseFilterCheck.isSelected()) match = textToSearch.contains(term);
                        else match = textToSearch.toLowerCase().contains(term.toLowerCase());
                    }
                    if (negativeFilterCheck.isSelected()) { if (match) return false; }
                    else { if (!match) return false; }
                }

                String hideLenText = hideLengthField.getText().trim();
                if (!hideLenText.isEmpty()) {
                    int lenIdx = tableModel.findColumn("Length");
                    if (lenIdx >= 0) {
                        Object lenObj = entry.getValue(lenIdx);
                        if (lenObj instanceof Integer) {
                            int len = (Integer) lenObj;
                            for (String part : hideLenText.split(",")) {
                                try { if (len == Integer.parseInt(part.trim())) return false; } catch (Exception ignored) {}
                            }
                        }
                    }
                }
                return true;
            }
        };
        tableSorter.setRowFilter(filter);
    }

    public void addResult(Map<String, Object> res) {
        int id = (int) res.get("id");
        byte[] response = (byte[]) res.get("response");
        resultsData.put(id, new byte[][]{(byte[]) res.get("request"), response});

        Object errorObj = res.get("error");
        String error = errorObj == null ? "" : String.valueOf(errorObj);
        List<Object> rowData = new ArrayList<>();
        rowData.add(id);

        Object payloadsObj = res.get("payloads");
        String[] payloads = payloadsObj instanceof String[] ? (String[]) payloadsObj : new String[0];
        if (currentMarkerPairs > 1) {
            for (int i = 0; i < currentMarkerPairs; i++) {
                String value = i < payloads.length ? payloads[i] : "";
                rowData.add(value == null ? "(base)" : value);
            }
        } else {
            String single = payloads.length > 0 ? payloads[0] : String.valueOf(res.get("payload"));
            rowData.add(single == null ? "" : single);
        }

        rowData.add(res.get("status"));
        rowData.add(res.get("time"));
        rowData.add(error);
        boolean isTimeout = error.toLowerCase().contains("timeout") || error.toLowerCase().contains("timed out");
        rowData.add(isTimeout ? "\u2713" : "");
        rowData.add(res.get("length"));
        rowData.add(res.get("wordlist") == null ? "" : res.get("wordlist"));

        String matchedListStr = "";
        String extractedStr = "";
        if (response != null) {
            String respStr = helpers.bytesToString(response);
            List<String> matchedTerms = new ArrayList<>();
            for (String s : currentMatchStrings) {
                boolean match = false;
                if (s.contains("*")) {
                    String regex = "(?s).*" + Pattern.quote(s).replace("\\*", ".*") + ".*";
                    try {
                        match = Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(respStr).matches();
                    } catch (Exception ignored) {}
                } else {
                    match = respStr.toLowerCase().contains(s.toLowerCase());
                }
                if (match) {
                    matchedTerms.add(s);
                }
            }
            matchedListStr = String.join(", ", matchedTerms);
            if (currentExtractPattern != null) {
                Matcher m = currentExtractPattern.matcher(respStr);
                if (m.find()) {
                    extractedStr = m.groupCount() > 0 ? m.group(1) : m.group();
                }
            }
        }
        rowData.add(matchedListStr);
        if (currentExtractPattern != null) {
            rowData.add(extractedStr);
        }
        
        SwingUtilities.invokeLater(() -> {
            tableModel.addRow(rowData.toArray());
            statusLabel.setText("Status: Running | Sent: " + id);
        });
    }

    public void onFinished() {
        SwingUtilities.invokeLater(() -> {
            resultsStopBtn.setEnabled(false);
            resultsPauseBtn.setEnabled(false);
            statusLabel.setText(statusLabel.getText().replace("Running", "Finished"));
        });
    }

    public void setPauseState(boolean paused) {
        resultsPauseBtn.setText(paused ? "Resume" : "Pause");
        if (paused) {
            statusLabel.setText(statusLabel.getText().replace("Running", "Paused"));
        } else {
            statusLabel.setText(statusLabel.getText().replace("Paused", "Running"));
        }
    }
    
    public void dispose() {
        if (frame != null) frame.dispose();
    }
}
