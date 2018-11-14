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

public class BurpExtender implements IBurpExtender, ITab, IMessageEditorController
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;
    
    private final JPanel borderPanel = new JPanel();
    private final ArrayList<BurpHttpMessage> messages = new ArrayList<>();

    
    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks){
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName("Logs");
               
        // obtain our output and error streams
        final PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        final PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
       
        // create our UI
        SwingUtilities.invokeLater(new Runnable(){
            
            @Override
            public void run(){
                final LogTableModel dataModel = new LogTableModel();

                JButton loadButton = new JButton("Load ...");
                loadButton.setPreferredSize(new Dimension(100, 30));
                final JFileChooser  fileDialog = new JFileChooser();
                loadButton.addActionListener( new ActionListener(){  
                    public void actionPerformed(ActionEvent e) {
                        int returnVal = fileDialog.showOpenDialog(borderPanel);
                        if (returnVal == JFileChooser.APPROVE_OPTION) {
                            File file = fileDialog.getSelectedFile();
                            try{
                                BufferedReader reader = new BufferedReader(new FileReader(file));
                                Scanner sc = new Scanner(reader);
                                // ISOLATE EACH HTTP MESSAGE
                                sc.useDelimiter("======================================================\r\n\r\n\r\n\r\n");                                                      
                                int n = 0;
                                // PARSE THE HTTP MESSAGE
                                while (sc.hasNext()) {
                                    stdout.println("|============[ HTTP MESSAGE ("+n+") ]============|");
                                    String http_message = sc.next();
                                    BurpHttpMessage HRR = new BurpHttpMessage(); 
                                    //
                                    // http_message MUST be in the following format:
                                    //
                                    // ======================================================
                                    // 22:27:52  https://bla.blabla.org:443  [127.0.0.1]
                                    // ======================================================
                                    // REQUEST  
                                    // ======================================================
                                    // RESPONSE (optional)
                                    // ======================================================\r\n\r\n\r\n\r\n
                                    //
                                    Scanner scanner = new Scanner(http_message);
                                    scanner.useDelimiter("======================================================\r\n");
                                    String http_msg_header = scanner.next();
                                    String[] tokens = http_msg_header.split("  ");
                                    
                                    byte[] request;
                                    byte[] response;
                                    
                                    String time = tokens[0];
                                    HRR.setTimeString(time);
                                    String host_ip = tokens[2];
                                    HRR.setHostIP(host_ip.substring(1,host_ip.length()-3));
                                                                              
                                    String service = tokens[1]; // SERVICE = PROTOCOL, HOST , PORT 
                                    try{
                                        URL baseURL = new URL(service);
                                        HRR.setUrl(baseURL);
                                        String protocol = baseURL.getProtocol();
                                        String host = baseURL.getHost();                                        
                                        int port = baseURL.getPort();
                                        IHttpService HttpService = new BurpHttpService(host,port,protocol);
                                        HRR.setHttpService(HttpService);
                                    }
                                    catch(MalformedURLException ex){
                                        ex.printStackTrace();
                                        stderr.println("[!] ERROR: MalformedURLException while processing a log entry header!");
                                    }
        
                                    if (scanner.hasNext()){
                                        //// PROCESS REQUEST ///////////////////////////////////////////////
                                        String http_msg_request = scanner.next();
                                        // dunno why http_msg_request comes with 2 extra bytes at the
                                        // end: 0d0a; substring -2 delete the extra newline
                                        request = helpers.stringToBytes(http_msg_request.substring(0,http_msg_request.length()-2));
                                        HRR.setRequest(request);
                                    }
                                    if (scanner.hasNext()){
                                        //// PROCESS RESPONSE //////////////////////////////////////////////
                                        String http_msg_response = scanner.next();
                                        // dunno why http_msg_response comes with 2 extra bytes at the
                                        // end: 0d0a; substring -2 delete the extra newline
                                        response = helpers.stringToBytes(http_msg_response.substring(0,http_msg_response.length()-2));
                                        HRR.setResponse(response);
                                    }
                                    else{
                                        response = helpers.stringToBytes("NO RESPONSE");
                                        HRR.setResponse(response);
                                    }
                                    if (scanner.hasNext()){
                                        // SCREAM ///////////////////////////////////////////////////////////
                                        stderr.println("[!] Something went wrong! Log entry with too many pieces!");
                                    }
                                    scanner.close();    
                                    dataModel.update(HRR);
                                    n++;
                                }
                                sc.close();
                            }catch (IOException exc) {
                                exc.printStackTrace();
                                stderr.println("[!] ERROR reading selected file!");
                            }
                        }
                        else {
                            stderr.println("[!] WARNING OpenDialog cancelled!");           
                        }
                    }
                });
                
                // Load button in a Flow Layout
                JPanel flowPanel = new JPanel(new FlowLayout());
                flowPanel.add(loadButton);
                
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
                callbacks.customizeUiComponent(loadButton);
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
        return "Logs";
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

    //
    // extend AbstractTableModel to draw the log table
    //    
    public class LogTableModel extends AbstractTableModel { 
        
        public LogTableModel(){
            super();
        }
        
        @Override
        public int getColumnCount(){ return 4; } 
        
        @Override
        public int getRowCount(){ return messages.size();} 
        
        @Override
        public Object getValueAt(int row,int col){
            switch (col){
                case 0:
                    return row;
                case 1:
                    return messages.get(row).getTimeString();
                case 2:
                    return messages.get(row).getProtocol()+"://"+messages.get(row).getHost();
                case 3:
                    return messages.get(row).getHostIP();
                default:
                    return "";
            } 
        }    
        
        @Override
        public String getColumnName(int columnIndex){
            switch(columnIndex){
                case 0:
                    return "#";
                case 1:
                    return "Time";
                case 2:
                    return "Host";
                case 3:
                    return "IP";
                default:
                    return "";
            }
        } 
        
        public void update(BurpHttpMessage m){
            messages.add(m);
            fireTableRowsInserted(1,1);
        } 
    } 
}//end BurpExtender
