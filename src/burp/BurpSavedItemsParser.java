package burp;

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// The BurpSavedItemsParser class, to parse saved-items files,
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
import java.io.InputStream;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.XMLConstants;

public class BurpSavedItemsParser extends BurpLogParser {
    
      	protected DocumentBuilderFactory dbf; 
	private DocumentBuilder db;

	BurpSavedItemsParser(File file, IBurpExtenderCallbacks callbacks, LogTableModel dataModel){
		super(file, callbacks, dataModel);
		this.dbf = DocumentBuilderFactory.newInstance();
		
    		this.helpers = callbacks.getHelpers();
	}

	public void run() {
        try {
		  // process XML securely, avoid attacks like XML External Entities (XXE)
		  this.dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		
		  // parse XML file
		  this.db = this.dbf.newDocumentBuilder();
		  Document doc = db.parse(this.logfile);
		  doc.getDocumentElement().normalize();
		  
		  // get <item>
		  System.out.println("------");
		  NodeList list = doc.getElementsByTagName("item");
		  for (int temp = 0; temp < list.getLength(); temp++) {
		      Node node = list.item(temp);
		      if (node.getNodeType() == Node.ELEMENT_NODE) {
			  Element item_element = (Element) node;
			  
			  // get host attribute
			  Element host_element = (Element) item_element.getElementsByTagName("host").item(0);
			  String ip = host_element.getAttribute("ip");
			  String host = host_element.getTextContent();
			  String time = item_element.getElementsByTagName("time").item(0).getTextContent();
			  String url = item_element.getElementsByTagName("url").item(0).getTextContent();
			  String protocol = item_element.getElementsByTagName("protocol").item(0).getTextContent();
			  String port = item_element.getElementsByTagName("port").item(0).getTextContent();
			  String request = item_element.getElementsByTagName("request").item(0).getTextContent();
			  String response = item_element.getElementsByTagName("response").item(0).getTextContent();
			  String comment = item_element.getElementsByTagName("comment").item(0).getTextContent();
		
			  /*
			  System.out.println("time: " + time); 
			  System.out.println("url: " + url); 
			  System.out.println("ip: " + ip); 
			  System.out.println("protocol: " + protocol); 
			  System.out.println("host: " + host); 
			  System.out.println("port: " + port); 
			  System.out.println("==== REQUEST ====: ");
			  System.out.println(request);
			  System.out.println("==== RESPONSE ====: ");
			  System.out.println(response);
			  System.out.println("==== Comments ====:\n" + comment);
			  */
			  
		  	  BurpHttpMessage HRR = new BurpHttpMessage(); 
			  HRR.setTimeString(time);
			  HRR.setHostIP(ip);
			  HRR.setUrl(new URL(url));
			  
			  IHttpService HttpService = new BurpHttpService(host,Integer.parseInt(port),protocol);
			  HRR.setHttpService(HttpService);
		 	  HRR.setRequest(helpers.base64Decode(request));
			  HRR.setResponse(helpers.base64Decode(response));

			  HRR.setComment(comment);

		  	  dataModel.update(HRR);

		      }
		      System.out.println("------");
		  }
		

		}catch (IOException exc) {
			exc.printStackTrace();
			stderr.println("[!] ERROR reading selected file!");
		} catch (ParserConfigurationException | SAXException e) {
		  	e.printStackTrace();
			stderr.println("[!] ERROR parsing XML!");
		}
        catch (Exception e) {
            stderr.println("Unknown Error: " + e.getMessage());
        }
        stdout.println("[+] Shutting down thread!");
	}

}//endclass
