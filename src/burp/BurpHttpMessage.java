package burp;

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Implement IHttpRequestResponse (the Burp's interface to represent
// HTTP messages), & some utilities.
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

import java.net.URL;

public class BurpHttpMessage implements IHttpRequestResponse{
    private String comment;
    private String highlight;   
    private BurpHttpService HttpService; // host, port, protocol.
    private byte[] request;
    private byte[] response;
    private URL url;            // contains the same info of BurpHttpService
    private short statusCode;
    private String method;
    private String time;
    private String host_ip;     // ip address of the dest 
    
    public BurpHttpMessage(){
    }

    @Override
   public byte[] getRequest() {
    return request;
   }

    @Override
   public void setRequest(byte[] request) {
      this.request = request;
   }

    @Override
   public byte[] getResponse() {
      return response;
   }

    @Override
   public void setResponse(byte[] response) {
      this.response = response;
   }

    @Override
   public String getComment() {
      return comment;
   }

    @Override
   public void setComment(String comment) {
      this.comment = comment;
   }

    @Override
   public String getHighlight() {
      return highlight;
   }

    @Override
   public void setHighlight(String highlight) {
      this.highlight = highlight;
   }

   @Override
   public IHttpService getHttpService() {
        return HttpService;
   }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.HttpService = (BurpHttpService) httpService;
    }
   
    public String getHost() {
      return HttpService.getHost();
   }

   public void setHost(String host) {
      this.HttpService.setHost(host);
   }

   public String getHostIP() {
      return host_ip;
   }

   public void setHostIP(String host) {
      this.host_ip = host;
   }
   
   public int getPort() {
      return HttpService.getPort();
   }

   public void setPort(int port) {
      this.HttpService.setPort(port);
   }

   public String getProtocol() {
      return HttpService.getProtocol();
   }

   public void setProtocol(String protocol) {
      this.HttpService.setProtocol(protocol);
   }

   public URL getUrl() {
      return url;
   }

   public void setUrl(URL url) {
      this.url = url;
   }

   public short getStatusCode() {
      return statusCode;
   }

   public void setStatusCode(short statusCode) {
      this.statusCode = statusCode;
   }
    
    public String getMethod() {
      return method;
   }

   public void setMethod(String method) {
      this.method = method;
   }
   
   public String getTimeString() {
      return time;
   }

   public void setTimeString(String time) {
      this.time = time;
   }
   
}//endclass
