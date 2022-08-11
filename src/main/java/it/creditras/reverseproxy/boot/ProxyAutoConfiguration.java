package it.creditras.reverseproxy.boot;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import it.creditras.reverseproxy.servlet.ProxyServlet3;
import it.creditras.reverseproxy.servlet.ProxyServlet;
import it.creditras.reverseproxy.servlet.Route;

/**
 * TODO: class description
 *
 * @author lucio.regina
 * @version 
 * @since
 *
 */
@Configuration
@ConfigurationProperties(prefix = "servlet-configurations")
public class ProxyAutoConfiguration {//implements EnvironmentAware{

    private List<String> urls = new ArrayList<String>();
    private List<Route> routes = new ArrayList<Route>();
    private boolean logging_enabled;
    
    @Value("${http_proxy:#{null}}")
    private String httpProxy;
    
    @Bean
    public ServletRegistrationBean servletRegistrationBean(){
      String[] u = urls.toArray(new String[urls.size()]);
      
      String hostName = getServerName();
      List<Route> routesTemp = new ArrayList<Route>();
      for(Route r : this.routes) {
    	  if(hostName.equalsIgnoreCase(r.getServerName())) routesTemp.add(r);
      }
      this.setRoutes(routesTemp);
      
      ServletRegistrationBean servletRegistrationBean = new ServletRegistrationBean(new ProxyServlet(this.routes), u);
      servletRegistrationBean.addInitParameter(ProxyServlet.P_LOG, String.valueOf(this.logging_enabled));
      if(httpProxy != null) {
    	  servletRegistrationBean.addInitParameter(ProxyServlet.P_HTTP_PROXY_HOST, httpProxy.split(":")[0]);
          servletRegistrationBean.addInitParameter(ProxyServlet.P_HTTP_PROXY_PORT, httpProxy.split(":")[1]);  
      }
      
      //Rimuovere le rotte non legate alla macchina indicata nella configuazione
      
      
      return servletRegistrationBean;
    }
    
    public String getServerName() {
    	String hostname = StringUtils.EMPTY;   	
    	try {
	    	String env = System.getenv("DEPLOY_ENV");
	    	if(env != null && env != StringUtils.EMPTY){
				hostname = env;
			} else {
				hostname = StringUtils.substringBefore(
	                    StringUtils.lowerCase(InetAddress.getLocalHost().getHostName()),
	                    ".");
			}
    	}catch(Exception e) {
    		
    	}
    	return hostname;
    }
    
    public void setUrls(List<String> urls) {
        this.urls = urls;
    }
    
    /**
     * @param routes the routes to set
     */
    public void setRoutes(List<Route> routes) {
        this.routes = routes;
    }

    /**
     * @param logging_enabled the logging_enabled to set
     */
    public void setLogging_enabled(boolean logging_enabled) {
        this.logging_enabled = logging_enabled;
    }

    /**
     * @return the urls
     */
    public List<String> getUrls() {
        return urls;
    }

    /**
     * @return the routes
     */
    public List<Route> getRoutes() {
        return routes;
    }

}
