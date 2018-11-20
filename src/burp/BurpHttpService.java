package burp;

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Implement IHttpService (the Burp's interface to provide PROTOCOL HOST PORT) 
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

public class BurpHttpService implements IHttpService{
    private String host;
    private int port;
    private String protocol;
    
        public BurpHttpService(String host, int port, String protocol){
            this.host = host;
            this.port = port;
            this.protocol = protocol;
        }
    
        @Override
        public String getHost() {
            return host;
        }
        
        public void setHost(String host) {
            this.host = host;
        }

        @Override
        public int getPort() {
            return port;
        }
        
        public void setPort(int port) {
            this.port = port;
        }
        
        @Override
        public String getProtocol() {
            return protocol;
        }
        
         public void setProtocol(String proto) {
            this.protocol = proto;
        }
}
