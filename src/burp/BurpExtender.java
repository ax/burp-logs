package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Scanner;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JFileChooser;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.File;

public class BurpExtender implements IBurpExtender, ITab, IMessageEditorController{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;
    
    private final JPanel borderPanel = new JPanel();
    private final ArrayList<BurpHttpMessage> messages = new ArrayList<>();
	private static final String name = "Log Viewer";  //Original name was Logs.
	private static final String version = "2.0";

    
    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks){
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName(name);
               
        // obtain our output and error streams
        final PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        final PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
       
        // create our UI
        SwingUtilities.invokeLater(new Runnable(){
            
            @Override
            public void run(){
                final LogTableModel dataModel = new LogTableModel(messages);
                final JFileChooser  fileDialog = new JFileChooser();

                //load files that were saved using "Project options > Misc > Logging"
		JButton loadMiscLogsButton = new JButton("Load Project Misc Logs");
                loadMiscLogsButton.addActionListener( new ActionListener(){  
                    public void actionPerformed(ActionEvent e) {
                        int returnVal = fileDialog.showOpenDialog(borderPanel);
                        if (returnVal == JFileChooser.APPROVE_OPTION) {
				final File logfile = fileDialog.getSelectedFile();

				BurpLogParser miscLogParser = new BurpLogParser(logfile,callbacks,dataModel);
				new Thread(miscLogParser).start();
				callbacks.registerExtensionStateListener(miscLogParser);

                        }
                        else {
                            stderr.println("[!] WARNING OpenDialog cancelled!");           
                        }
                    }
                });


                //load files that were saved using "Saved Items"
		JButton loadSavedItemsButton = new JButton("Load Saved Items");
                loadSavedItemsButton.addActionListener( new ActionListener(){  
                    public void actionPerformed(ActionEvent e) {
                        int returnVal = fileDialog.showOpenDialog(borderPanel);
                        if (returnVal == JFileChooser.APPROVE_OPTION) {
				final File logfile = fileDialog.getSelectedFile();

				BurpSavedItemsParser savedItemsParser = new BurpSavedItemsParser(logfile,callbacks,dataModel);
				new Thread(savedItemsParser).start();
				callbacks.registerExtensionStateListener(savedItemsParser);


                        }
                        else {
                            stderr.println("[!] WARNING OpenDialog cancelled!");           
                        }
                    }
                });


                // Load button in a Flow Layout
                JPanel flowPanel = new JPanel(new FlowLayout());
                flowPanel.add(loadMiscLogsButton);
                flowPanel.add(loadSavedItemsButton);
                
               // Vertical JSplitPane with log table and tabs 
                JSplitPane verSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                // table of log entries
                Table logTable = new Table(dataModel);
                JScrollPane scrollPane = new JScrollPane(logTable);
                verSplitPane.setLeftComponent(scrollPane);
                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                verSplitPane.setRightComponent(tabs); 
                
                // Container with the flowPanel and the verSplitPane 
                borderPanel.setLayout(new BorderLayout());
                borderPanel.add(flowPanel,BorderLayout.NORTH);
                borderPanel.add(verSplitPane,BorderLayout.CENTER);
                
                // customize our UI components
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(tabs);
                callbacks.customizeUiComponent(flowPanel);
                callbacks.customizeUiComponent(verSplitPane);
                callbacks.customizeUiComponent(loadMiscLogsButton);
                callbacks.customizeUiComponent(loadSavedItemsButton);
                callbacks.customizeUiComponent(borderPanel);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
                callbacks.issueAlert("Loaded!");        
            }// end run
        });
    }

    //
    // implement ITab
    //
    @Override
    public String getTabCaption(){
        return BurpExtender.name;
    }

    @Override
    public Component getUiComponent(){
        return borderPanel;
    }
   
    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages
    // being displayed (to support context menu actions, etc.).
    //
    
    @Override
    public byte[] getRequest(){
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse(){
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService(){
        return currentlyDisplayedItem.getHttpService();
    }

    //
    // extend JTable to handle cell selection
    //
    private class Table extends JTable{
        public Table(TableModel tableModel){
            super(tableModel);
        }
        
        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend){
            // show the log entry for the selected row
            BurpHttpMessage entry = messages.get(row);
            requestViewer.setMessage(entry.getRequest(), true);
            responseViewer.setMessage(entry.getResponse(), false);
            currentlyDisplayedItem = (IHttpRequestResponse) entry;
            super.changeSelection(row, col, toggle, extend);
        }  
    }

 
}//end BurpExtender
