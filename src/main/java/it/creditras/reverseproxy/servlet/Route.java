package it.creditras.reverseproxy.servlet;

import java.net.URI;

import org.apache.http.HttpHost;

/**
 * TODO: class description
 *
 * @author lucio.regina
 * @version 
 * @since
 *
 */
public class Route {

	public static final String CPT_ROOT = "root";
	public static final String CPT_REWRITE = "rewrite";
	public static final String CPT_USER_SOURCE = "useSource";
	public static final String CPT_PASS_TOMCAT = "PassTomcat";
	public static final String CT_XML="XML";
	
    private String source;
    private String destination;
    private URI targetUriObj;
    private HttpHost targetHost;
    private String regexp;
    private String contentType;
    private String contextPathType;
    private String serverName;
    /**
     * @return the source
     */
    public String getSource() {
        return source;
    }
    
    /**
     * @param source the source to set
     */
    public void setSource(String source) {
        this.source = source;
    }
    
    /**
     * @return the destination
     */
    public String getDestination() {
        return destination;
    }
    
    /**
     * @param destination the destination to set
     */
    public void setDestination(String destination) {
        this.destination = destination;
    }

    
    /**
     * @return the targetUriObj
     */
    public URI getTargetUriObj() {
        return targetUriObj;
    }

    
    /**
     * @param targetUriObj the targetUriObj to set
     */
    public void setTargetUriObj(URI targetUriObj) {
        this.targetUriObj = targetUriObj;
    }

    /**
     * @return the targetHost
     */
    public HttpHost getTargetHost() {
        return targetHost;
    }
    
    /**
     * @param targetHost the targetHost to set
     */
    public void setTargetHost(HttpHost targetHost) {
        this.targetHost = targetHost;
    }
    
    /**
     * @return the regexp
     */
    public String getRegexp() {
        return regexp;
    }

    
    /**
     * @param regexp the regexp to set
     */
    public void setRegexp(String regexp) {
        this.regexp = regexp;
    }

	public String getContentType() {
		return contentType;
	}

	public void setContentType(String contentType) {
		this.contentType = contentType;
	}

	public String getContextPathType() {
		return contextPathType;
	}

	public void setContextPathType(String contextPathType) {
		this.contextPathType = contextPathType;
	}

	public String getServerName() {
		return serverName;
	}

	public void setServerName(String serverName) {
		this.serverName = serverName;
	}
    
    
}
