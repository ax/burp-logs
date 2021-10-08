package burp;

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// The BurpLogParser class, to parse log files,
// an instance of this class is intended to be executed by a Java Thread.
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

import java.util.Scanner;
import java.io.File;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.io.FileReader;
import java.net.URL;
import java.net.MalformedURLException;
import java.io.IOException;


public class BurpLogParser implements Runnable, IExtensionStateListener{
	protected IBurpExtenderCallbacks callbacks;
	protected IExtensionHelpers helpers;
	protected File logfile;
	protected LogTableModel dataModel;
	protected PrintWriter stdout;
	protected PrintWriter stderr;
    
	BurpLogParser(File file, IBurpExtenderCallbacks callbacks, LogTableModel dataModel){
		this.logfile = file;
		this.callbacks = callbacks;
		this.dataModel = dataModel;
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
    		this.stderr = new PrintWriter(callbacks.getStderr(), true);
	}

	public void run() {
        try {
    			helpers = callbacks.getHelpers();
			BufferedReader reader = new BufferedReader(new FileReader(logfile));
			Scanner sc = new Scanner(reader);

			// ISOLATE EACH HTTP MESSAGE
			sc.useDelimiter("======================================================\r\n\r\n\r\n\r\n"); 
			int n = 0;
			// PARSE THE HTTP MESSAGE
			while (sc.hasNext()) {
				stdout.println("[+] HTTP MESSAGE ("+n+")");
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
					stderr.println("[!] Something went wrong! Log entry with too many pieces! ("+n+")");
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
        catch (Exception e) {
            stderr.println("Error: "+e.getMessage());
        }
        stdout.println("[+] Shutting down thread!");
	}

	@Override
	public void extensionUnloaded() {
        stdout.println("Extension unloading - Abort thread!");
        Thread.currentThread().interrupt();
	}
}//endclass
