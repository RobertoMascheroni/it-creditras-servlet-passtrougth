package it.creditras.reverseproxy.servlet;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.BitSet;
import java.util.Enumeration;
import java.util.Formatter;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Result;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.AbortableHttpRequest;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.HttpHostConnectException;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.message.HeaderGroup;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.util.EntityUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO: class description
 *
 * @author Lucio Regina
 * @version 
 * @since
 *
 */
public class ProxyServlet extends HttpServlet{
    
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    /**
     * Constructs an instance of this class. 
     *
     */
    public ProxyServlet(List<Route> routes) {
        this.routes = routes;
    }

    private static final long serialVersionUID = 1L;

    /* INIT PARAMETER NAME CONSTANTS */

    /** A boolean parameter name to enable logging of input and target URLs to the servlet log. */
    public static final String P_LOG = "log";

    /** A boolean parameter name to enable forwarding of the client IP  */
    public static final String P_FORWARDEDFOR = "forwardip";

    /** A boolean parameter name to keep HOST parameter as-is  */
    public static final String P_PRESERVEHOST = "preserveHost";

    /** A boolean parameter name to keep COOKIES as-is  */
    public static final String P_PRESERVECOOKIES = "preserveCookies";

    /** A boolean parameter name to have auto-handle redirects */
    public static final String P_HANDLEREDIRECTS = "http.protocol.handle-redirects"; // ClientPNames.HANDLE_REDIRECTS

    /** A integer parameter name to set the socket connection timeout (millis) */
    public static final String P_CONNECTTIMEOUT = "http.socket.timeout"; // CoreConnectionPNames.SO_TIMEOUT

    /** A integer parameter name to set the socket read timeout (millis) */
    public static final String P_READTIMEOUT = "http.read.timeout";

    /** The parameter name for the target (destination) URI to proxy to. */
    protected static final String P_TARGET_URI = "targetUri";

    public static final String P_HTTP_PROXY_HOST = "targetHTTPProxyHost";
    public static final String P_HTTP_PROXY_PORT = "targetHTTPProxyPort";

    /* MISC */

    protected boolean doLog = false;
    protected boolean doForwardIP = true;
    /** User agents shouldn't send the url fragment but what if it does? */
    protected boolean doSendUrlFragment = true;
    protected boolean doPreserveHost = false;
    protected boolean doPreserveCookies = false;
    protected boolean doHandleRedirects = false;
    protected int connectTimeout = -1;
    protected int readTimeout = -1;
    
    protected String httpProxyHost = "";    
    protected int httpProxyPort = -1;

    //These next 3 are cached here, and should only be referred to in initialization logic. See the
    // ATTR_* parameters.
    /** From the configured parameter "targetUri". */
//    protected String targetUri;
    private List<Route> routes;
//    protected URI targetUriObj;//new URI(targetUri)
//    protected HttpHost targetHost;//URIUtils.extractHost(targetUriObj);

    private HttpClient proxyClient;


    /**
     * Reads a configuration parameter. By default it reads servlet init parameters but
     * it can be overridden.
     */
    protected String getConfigParam(String key) {
        return getServletConfig().getInitParameter(key);
    }

    @Override
    public void init() throws ServletException {
        String doLogStr = getConfigParam(P_LOG);
        if (doLogStr != null) {
            this.doLog = Boolean.parseBoolean(doLogStr);
        }

        String doForwardIPString = getConfigParam(P_FORWARDEDFOR);
        if (doForwardIPString != null) {
            this.doForwardIP = Boolean.parseBoolean(doForwardIPString);
        }

        String preserveHostString = getConfigParam(P_PRESERVEHOST);
        if (preserveHostString != null) {
            this.doPreserveHost = Boolean.parseBoolean(preserveHostString);
        }

        String preserveCookiesString = getConfigParam(P_PRESERVECOOKIES);
        if (preserveCookiesString != null) {
            this.doPreserveCookies = Boolean.parseBoolean(preserveCookiesString);
        }

        String handleRedirectsString = getConfigParam(P_HANDLEREDIRECTS);
        if (handleRedirectsString != null) {
            this.doHandleRedirects = Boolean.parseBoolean(handleRedirectsString);
        }

        String connectTimeoutString = getConfigParam(P_CONNECTTIMEOUT);
        if (connectTimeoutString != null) {
            this.connectTimeout = Integer.parseInt(connectTimeoutString);
        }

        String readTimeoutString = getConfigParam(P_READTIMEOUT);
        if (readTimeoutString != null) {
            this.readTimeout = Integer.parseInt(readTimeoutString);
        }

        if (getConfigParam(P_HTTP_PROXY_HOST) != null) {
        	this.httpProxyHost = getConfigParam(P_HTTP_PROXY_HOST);
        }
        
        if (getConfigParam(P_HTTP_PROXY_PORT) != null) {
        	this.httpProxyPort =  Integer.parseInt(getConfigParam(P_HTTP_PROXY_PORT));
        }
        
        initTarget();//sets target*

        try {
            proxyClient = createHttpClient(buildRequestConfig());
        }
        catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
        }
    }

    protected void initTarget() throws ServletException {
        routes.stream().forEach(r -> {
            try {
                r.setTargetUriObj(new URI(r.getDestination()));
                r.setTargetHost(URIUtils.extractHost(r.getTargetUriObj()));
            }
            catch (URISyntaxException e) {
                e.printStackTrace();
            }
            
        });
//        targetUri = getConfigParam(P_TARGET_URI);
//        if (targetUri == null)
//            throw new ServletException(P_TARGET_URI+" is required.");
//        //test it's valid
//        try {
//            targetUriObj = new URI(targetUri);
//        } catch (Exception e) {
//            throw new ServletException("Trying to process targetUri init parameter: "+e,e);
//        }
//        targetHost = URIUtils.extractHost(targetUriObj);
    }

    /**
     * Sub-classes can override specific behaviour of {@link org.apache.http.client.config.RequestConfig}.
     */
    protected RequestConfig buildRequestConfig() {
        RequestConfig.Builder builder = RequestConfig.custom()
                .setRedirectsEnabled(doHandleRedirects)
                .setCookieSpec(CookieSpecs.IGNORE_COOKIES) // we handle them in the servlet instead
                .setConnectTimeout(connectTimeout)
                .setSocketTimeout(readTimeout);
        return builder.build();
    }

    /**
     * Sub-classes can override specific behaviour of {@link org.apache.http.config.SocketConfig}.
     */
    protected SocketConfig buildSocketConfig() {

      if (readTimeout < 1) {
        return null;
      }

      return SocketConfig.custom()
              .setSoTimeout(readTimeout)
              .build();
    }

    /**
     * Creates a {@code HttpClientBuilder}. Meant as preprocessor to possibly
     * adapt the client builder prior to any configuration got applied.
     *
     * @return HttpClient builder
     */
    protected HttpClientBuilder getHttpClientBuilder() {
      return HttpClientBuilder.create();
    }
    
    /** Called from {@link #init(javax.servlet.ServletConfig)}.
     *  HttpClient offers many opportunities for customization.
     *  In any case, it should be thread-safe.
     * @throws KeyStoreException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyManagementException 
     **/
    protected HttpClient createHttpClient(final RequestConfig requestConfig) throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
    	HttpClientBuilder builder = HttpClientBuilder.create();
    	if(httpProxyHost != null && httpProxyPort > -1) {
    		builder.setProxy(new HttpHost(httpProxyHost, httpProxyPort));
    	}
    	
    	builder.setDefaultRequestConfig(requestConfig).setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
    	.setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy()
    	{
    		public boolean isTrusted(X509Certificate[] arg0, String arg1) throws CertificateException
    		{
    			return true;
    		}
    	}).build());
    	
    	return builder.build();            
    }

    /** The http client used.
     * @see #createHttpClient(RequestConfig) */
    protected HttpClient getProxyClient() {
        return proxyClient;
    }

    @Override
    public void destroy() {
        //Usually, clients implement Closeable:
        try {
            ((Closeable) proxyClient).close();
        } catch (IOException e) {
            log("While destroying servlet, shutting down HttpClient: "+e, e);
        }
        super.destroy();
    }
    
    @Override
    protected void service(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
        throws ServletException, IOException {
      // Make the Request
      //note: we won't transfer the protocol version because I'm not sure it would truly be compatible
      String method = servletRequest.getMethod();
      String proxyRequestUri = rewriteUrlFromRequest(servletRequest);
      HttpRequest proxyRequest;
      //spec: RFC 2616, sec 4.3: either of these two headers signal that there is a message body.
      if (servletRequest.getHeader(HttpHeaders.CONTENT_LENGTH) != null ||
          servletRequest.getHeader(HttpHeaders.TRANSFER_ENCODING) != null) {
          if(servletRequest.getParameterNames().hasMoreElements() && !proxyRequestUri.contains("?wsdl")){
              proxyRequest = newProxyRequestWithParameters(method, proxyRequestUri, servletRequest);
          }else{
              proxyRequest = newProxyRequestWithEntity(method, proxyRequestUri, servletRequest);      
          }
      } else {
        proxyRequest = new BasicHttpRequest(method, proxyRequestUri);
      }
      copyRequestHeaders(servletRequest, proxyRequest);

      setXForwardedForHeader(servletRequest, proxyRequest);

      HttpResponse proxyResponse = null;
      try {
        // Execute the request
        proxyResponse = doExecute(servletRequest, servletResponse, proxyRequest);

        // Process the response:

        // Pass the response code. This method with the "reason phrase" is deprecated but it's the
        //   only way to pass the reason along too.
        int statusCode = proxyResponse.getStatusLine().getStatusCode();
        //noinspection deprecation
        servletResponse.setStatus(statusCode, proxyResponse.getStatusLine().getReasonPhrase());

        // Copying response headers to make sure SESSIONID or other Cookie which comes from the remote
        // server will be saved in client when the proxied url was redirected to another one.
        // See issue [#51](https://github.com/mitre/HTTP-Proxy-Servlet/issues/51)
        copyResponseHeaders(proxyResponse, servletRequest, servletResponse);

        if (statusCode == HttpServletResponse.SC_NOT_MODIFIED) {
          // 304 needs special handling.  See:
          // http://www.ics.uci.edu/pub/ietf/http/rfc1945.html#Code304
          // Don't send body entity/content!
          servletResponse.setIntHeader(HttpHeaders.CONTENT_LENGTH, 0);
        } else {
          // Send the content to the client
          copyResponseEntity(proxyResponse, servletResponse, proxyRequest, servletRequest);
        }

      }
      catch (Exception e) {
        //abort request, according to best practice with HttpClient
    	logger.error("**********************************************");
    	logger.error("ERRORE -> " + e.getMessage());
    	logger.error("**********************************************");
		if (proxyRequest instanceof AbortableHttpRequest) {
		  AbortableHttpRequest abortableHttpRequest = (AbortableHttpRequest) proxyRequest;
		  abortableHttpRequest.abort();
		}
		if (e instanceof RuntimeException)
		  throw (RuntimeException)e;
		if (e instanceof ServletException)
		  throw (ServletException)e;
		//noinspection ConstantConditions
		if (e instanceof IOException)
		  throw (IOException) e;
		throw new RuntimeException(e);

      } finally {
        // make sure the entire entity was consumed, so the connection is released   	
        if (proxyResponse != null)
          consumeQuietly(proxyResponse.getEntity());
        //Note: Don't need to close servlet outputStream:
        // http://stackoverflow.com/questions/1159168/should-one-call-close-on-httpservletresponse-getoutputstream-getwriter
      }
    }

    protected HttpResponse doExecute(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
                                     HttpRequest proxyRequest) throws IOException {
      if (doLog) {
          logger.info("proxy " + servletRequest.getMethod() + " uri: " + servletRequest.getRequestURI() + " -- " +
                proxyRequest.getRequestLine().getUri());
      }
      return proxyClient.execute(getTargetHost(servletRequest), proxyRequest);
    }

    protected HttpRequest newProxyRequestWithEntity(String method, String proxyRequestUri,
                                                  HttpServletRequest servletRequest)
            throws IOException {
      HttpEntityEnclosingRequest eProxyRequest =
              new BasicHttpEntityEnclosingRequest(method, proxyRequestUri);
      // Add the input entity (streamed)
      //  note: we don't bother ensuring we close the servletInputStream since the container handles it
      eProxyRequest.setEntity(
              new InputStreamEntity(servletRequest.getInputStream(), getContentLength(servletRequest)));

      return eProxyRequest;
    }
    
    protected HttpRequest newProxyRequestWithParameters(String method, String proxyRequestUri,
            HttpServletRequest servletRequest)
                    throws IOException {
        HttpEntityEnclosingRequest eProxyRequest =
                new BasicHttpEntityEnclosingRequest(method, proxyRequestUri);

        StringBuilder postData = new StringBuilder();
        for (Map.Entry<String,String[]> param : servletRequest.getParameterMap().entrySet()) {
            if (postData.length() != 0) postData.append('&');
            postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            postData.append('=');
            postData.append(URLEncoder.encode(String.valueOf(param.getValue()[0]), "UTF-8"));
        }

        eProxyRequest.setEntity(
                new InputStreamEntity(new ByteArrayInputStream(postData.toString().getBytes("UTF-8"))));
        return eProxyRequest;
    }
    
    // Get the header value as a long in order to more correctly proxy very large requests
    private long getContentLength(HttpServletRequest request) {
      String contentLengthHeader = request.getHeader("Content-Length");
      if (contentLengthHeader != null) {
        return Long.parseLong(contentLengthHeader);
      }
      return -1L;
    }

    protected void closeQuietly(Closeable closeable) {
      try {
        closeable.close();
      } catch (IOException e) {
        log(e.getMessage(), e);
      }
    }

    /** HttpClient v4.1 doesn't have the
     * {@link org.apache.http.util.EntityUtils#consumeQuietly(org.apache.http.HttpEntity)} method. */
    protected void consumeQuietly(HttpEntity entity) {
      try {
        EntityUtils.consume(entity);
      } catch (IOException e) {//ignore
        log(e.getMessage(), e);
      }
    }

    /** These are the "hop-by-hop" headers that should not be copied.
     * http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
     * I use an HttpClient HeaderGroup class instead of Set&lt;String&gt; because this
     * approach does case insensitive lookup faster.
     */
    protected static final HeaderGroup hopByHopHeaders;
    static {
      hopByHopHeaders = new HeaderGroup();
      String[] headers = new String[] {
          "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
          "TE", "Trailers", "Transfer-Encoding", "Upgrade","Content-Length" };
      for (String header : headers) {
        hopByHopHeaders.addHeader(new BasicHeader(header, null));
      }
    }

    /** 
     * Copy request headers from the servlet client to the proxy request. 
     * This is easily overridden to add your own.
     */
    protected void copyRequestHeaders(HttpServletRequest servletRequest, HttpRequest proxyRequest) {
      // Get an Enumeration of all of the header names sent by the client
      @SuppressWarnings("unchecked")
      Enumeration<String> enumerationOfHeaderNames = servletRequest.getHeaderNames();
      while (enumerationOfHeaderNames.hasMoreElements()) {
        String headerName = enumerationOfHeaderNames.nextElement();
        copyRequestHeader(servletRequest, proxyRequest, headerName);
      }
    }

    /**
     * Copy a request header from the servlet client to the proxy request.
     * This is easily overridden to filter out certain headers if desired.
     */
    protected void copyRequestHeader(HttpServletRequest servletRequest, HttpRequest proxyRequest,
                                     String headerName) {
      //Instead the content-length is effectively set via InputStreamEntity
      if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH))
        return;
      if (hopByHopHeaders.containsHeader(headerName))
        return;

      @SuppressWarnings("unchecked")
      Enumeration<String> headers = servletRequest.getHeaders(headerName);
      while (headers.hasMoreElements()) {//sometimes more than one value
        String headerValue = headers.nextElement();
        // In case the proxy host is running multiple virtual servers,
        // rewrite the Host header to ensure that we get content from
        // the correct virtual server
        if (!doPreserveHost && headerName.equalsIgnoreCase(HttpHeaders.HOST)) {
          HttpHost host = getTargetHost(servletRequest);
          headerValue = host.getHostName();
          if (host.getPort() != -1)
            headerValue += ":"+host.getPort();
        } else if (!doPreserveCookies && headerName.equalsIgnoreCase(org.apache.http.cookie.SM.COOKIE)) {
          headerValue = getRealCookie(headerValue);
        }
        proxyRequest.addHeader(headerName, headerValue);
      }
    }

    private void setXForwardedForHeader(HttpServletRequest servletRequest,
                                        HttpRequest proxyRequest) {
      if (doForwardIP) {
        String forHeaderName = "X-Forwarded-For";
        String forHeader = servletRequest.getRemoteAddr();
        String existingForHeader = servletRequest.getHeader(forHeaderName);
        if (existingForHeader != null) {
          forHeader = existingForHeader + ", " + forHeader;
        }
        proxyRequest.setHeader(forHeaderName, forHeader);

        String protoHeaderName = "X-Forwarded-Proto";
        String protoHeader = servletRequest.getScheme();
        proxyRequest.setHeader(protoHeaderName, protoHeader);
      }
    }

    /** Copy proxied response headers back to the servlet client. */
    protected void copyResponseHeaders(HttpResponse proxyResponse, HttpServletRequest servletRequest,
                                       HttpServletResponse servletResponse) {
      for (Header header : proxyResponse.getAllHeaders()) {
        copyResponseHeader(servletRequest, servletResponse, header);
      }
    }

    /** Copy a proxied response header back to the servlet client.
     * This is easily overwritten to filter out certain headers if desired.
     */
    protected void copyResponseHeader(HttpServletRequest servletRequest,
                                    HttpServletResponse servletResponse, Header header) {
      String headerName = header.getName();
      if (hopByHopHeaders.containsHeader(headerName))
        return;
      String headerValue = header.getValue();
      if (headerName.equalsIgnoreCase(org.apache.http.cookie.SM.SET_COOKIE) ||
              headerName.equalsIgnoreCase(org.apache.http.cookie.SM.SET_COOKIE2)) {
        copyProxyCookie(servletRequest, servletResponse, headerValue);
      } else if (headerName.equalsIgnoreCase(HttpHeaders.LOCATION)) {
        // LOCATION Header may have to be rewritten.
        servletResponse.addHeader(headerName, rewriteUrlFromResponse(servletRequest, headerValue));
      } else {
        servletResponse.addHeader(headerName, headerValue);
      }
    }

    /** Copy cookie from the proxy to the servlet client.
     *  Replaces cookie path to local path and renames cookie to avoid collisions.
     */
    protected void copyProxyCookie(HttpServletRequest servletRequest,
                                   HttpServletResponse servletResponse, String headerValue) {
      List<HttpCookie> cookies = HttpCookie.parse(headerValue);
      String path = servletRequest.getContextPath(); // path starts with / or is empty string
      path += servletRequest.getServletPath(); // servlet path starts with / or is empty string
      if(path.isEmpty()){
          path = "/";
      }

      for (HttpCookie cookie : cookies) {
        //set cookie name prefixed w/ a proxy value so it won't collide w/ other cookies
        String proxyCookieName = doPreserveCookies ? cookie.getName() : getCookieNamePrefix(cookie.getName()) + cookie.getName();
        Cookie servletCookie = new Cookie(proxyCookieName, cookie.getValue());
        servletCookie.setComment(cookie.getComment());
        servletCookie.setMaxAge((int) cookie.getMaxAge());
        servletCookie.setPath(path); //set to the path of the proxy servlet
        // don't set cookie domain
        servletCookie.setSecure(cookie.getSecure());
        servletCookie.setVersion(cookie.getVersion());
        servletResponse.addCookie(servletCookie);
      }
    }

    /** Take any client cookies that were originally from the proxy and prepare them to send to the
     * proxy.  This relies on cookie headers being set correctly according to RFC 6265 Sec 5.4.
     * This also blocks any local cookies from being sent to the proxy.
     */
    protected String getRealCookie(String cookieValue) {
      StringBuilder escapedCookie = new StringBuilder();
      String cookies[] = cookieValue.split("[;,]");
      for (String cookie : cookies) {
        String cookieSplit[] = cookie.split("=");
        if (cookieSplit.length == 2) {
          String cookieName = cookieSplit[0].trim();
          if (cookieName.startsWith(getCookieNamePrefix(cookieName))) {
            cookieName = cookieName.substring(getCookieNamePrefix(cookieName).length());
            if (escapedCookie.length() > 0) {
              escapedCookie.append("; ");
            }
            escapedCookie.append(cookieName).append("=").append(cookieSplit[1].trim());
          }
        }
      }
      return escapedCookie.toString();
    }

    /** The string prefixing rewritten cookies. */
    protected String getCookieNamePrefix(String name) {
      return "!Proxy!" + getServletConfig().getServletName();
    }

//    /** Copy response body data (the entity) from the proxy to the servlet client. */
//    protected void copyResponseEntity(HttpResponse proxyResponse, HttpServletResponse servletResponse,
//                                      HttpRequest proxyRequest, HttpServletRequest servletRequest)
//            throws IOException {
//      HttpEntity entity = proxyResponse.getEntity();
//      if (entity != null) {
//        if (entity.isChunked()) {
//          // Flush intermediate results before blocking on input -- needed for SSE
//          InputStream is = entity.getContent();
//          OutputStream os = servletResponse.getOutputStream();
//          byte[] buffer = new byte[10 * 1024];
//          int read;
//          while ((read = is.read(buffer)) != -1) {
//            os.write(buffer, 0, read);
//            /*-
//             * Issue in Apache http client/JDK: if the stream from client is
//             * compressed, apache http client will delegate to GzipInputStream.
//             * The #available implementation of InflaterInputStream (parent of
//             * GzipInputStream) return 1 until EOF is reached. This is not
//             * consistent with InputStream#available, which defines:
//             *
//             *   A single read or skip of this many bytes will not block,
//             *   but may read or skip fewer bytes.
//             *
//             *  To work around this, a flush is issued always if compression
//              *  is handled by apache http client
//             */
//            if (true || is.available() == 0 /* next is.read will block */) {
//              os.flush();
//            }
//          }
//          // Entity closing/cleanup is done in the caller (#service)
//        } else {
//          OutputStream servletOutputStream = servletResponse.getOutputStream();
//          entity.writeTo(servletOutputStream);
//        }
//      }
//    }

    //** Copy response body data (the entity) from the proxy to the servlet client. *//*
    protected void copyResponseEntity(HttpResponse proxyResponse, HttpServletResponse servletResponse,
                                      HttpRequest proxyRequest, HttpServletRequest servletRequest)
            throws IOException {
      HttpEntity entity = proxyResponse.getEntity();
      Route r = getTargetUri(servletRequest);
      Charset charset = Charset.forName(servletResponse.getCharacterEncoding());
      if (entity != null) {
    	  if(proxyResponse.getHeaders("Content-Type").length > 0 && (proxyResponse.getHeaders("Content-Type")[0]).toString().contains("text/html") 
    			  && "text/html".equals(r.getContentType())) {
    		  ByteArrayOutputStream bos = new ByteArrayOutputStream();  
        	  entity.writeTo(bos);
    		  String responseBody = StringUtils.toEncodedString(bos.toByteArray(), charset);

    		  logger.info(" ============================== Page PRE parse ============================== ");
    		  logger.info(responseBody);
    		  logger.info(" ============================== Page PRE parse ============================== ");
    		  Document html = Jsoup.parse(responseBody);
    		  html.select("link").stream().forEach(l -> {
    			  l.attr("href", "/atomo-dev.apps.adp.allianz/".concat(l.attr("href")));
    		  });
    		  html.select("script").stream().forEach(s -> {
    			  s.attr("src", "/atomo-dev.apps.adp.allianz/".concat(s.attr("src")));
    		  });
    		  logger.info(" ============================== Page POST parse ============================== ");
    		  logger.info(html.outerHtml());
    		  logger.info(" ============================== Page POST parse ============================== ");
    		  byte[] out = html.html().getBytes();
    		  servletResponse.setContentLength(out.length);
    		  servletResponse.getOutputStream().write(out, 0, out.length);
    		  servletResponse.getOutputStream().flush();
    		  servletResponse.getOutputStream().close();
    	  }else if(proxyResponse.getHeaders("Content-Type").length > 0 && (
    			  (proxyResponse.getHeaders("Content-Type")[0]).toString().contains("application/javascript")
    			  || (proxyResponse.getHeaders("Content-Type")[0]).toString().contains("text/css")
    			  ||(proxyResponse.getHeaders("Content-Type")[0]).toString().contains("application/json")
    			  )){
    		  ByteArrayOutputStream bos = new ByteArrayOutputStream();  
        	  entity.writeTo(bos);
    		  String responseBody = StringUtils.toEncodedString(bos.toByteArray(), charset);
    		  Matcher m = Pattern.compile("\\'(\\$/.*?/)[^/]*?\\.\\S*\\'").matcher(responseBody);
    		  while (m.find()) {
                  String value = m.group();
                  responseBody.replaceAll(value, "/atomo-dev.apps.adp.allianz/".concat(value));
              }
    		  byte[] out = responseBody.getBytes();
    		  servletResponse.setContentLength(out.length);
    		  servletResponse.getOutputStream().write(out, 0, out.length);
    		  servletResponse.getOutputStream().flush();
    		  servletResponse.getOutputStream().close();
    	  }else {
    		  if(servletRequest.getRequestURI().indexOf(".idq")!=-1){
    	          logger.info("Servlet IDQ");
    			  
        		  ByteArrayOutputStream bos = new ByteArrayOutputStream();  
            	  entity.writeTo(bos);
        		  String responseBody = StringUtils.toEncodedString(bos.toByteArray(), charset);
        		  responseBody = responseBody+"\r\n";
        		  byte[] out = responseBody.getBytes();
//        		  servletResponse.setContentLength(out.length);
        		  servletResponse.getOutputStream().write(out, 0, out.length); 		  
        		  servletResponse.getOutputStream().flush();
        		  servletResponse.getOutputStream().close();

        		  //throw new IOException();
    			  
    		  }else {
    			  logger.info("Servlet NON IDQ");
    			  entity.writeTo(servletResponse.getOutputStream());
    		  }
    	  }
    	
      }
    }

    /** Reads the request URI from {@code servletRequest} and rewrites it, considering targetUri.
     * It's used to make the new request.
     */
    protected String rewriteUrlFromRequest(HttpServletRequest servletRequest) {
      StringBuilder uri = new StringBuilder(500);
      Route r = getTargetUri(servletRequest);
      uri.append(r.getDestination());
      // Handle the path given to the servlet
      if(Route.CPT_ROOT.equals(r.getContextPathType())) {
    	  uri.append(servletRequest.getRequestURI());
      }else if(Route.CPT_USER_SOURCE.equals(r.getContextPathType())) {
    	  uri.append(r.getSource());
      }else if(Route.CPT_PASS_TOMCAT.equals(r.getContextPathType())) {
    	  uri.append(r.getSource() + encodeUriQuery(servletRequest.getPathInfo()));
      }
      else {
	      if (servletRequest.getPathInfo() != null) {//ex: /my/path.html
	        uri.append(encodeUriQuery(servletRequest.getPathInfo().replaceFirst(r.getRegexp(), ""))); 
	      }
      }
      // Handle the query string & fragment
      String queryString = servletRequest.getQueryString();//ex:(following '?'): name=value&foo=bar#fragment
      String fragment = null;
      //split off fragment from queryString, updating queryString if found
      if (queryString != null) {
        int fragIdx = queryString.indexOf('#');
        if (fragIdx >= 0) {
          fragment = queryString.substring(fragIdx + 1);
          queryString = queryString.substring(0,fragIdx);
        }
      }

      queryString = rewriteQueryStringFromRequest(servletRequest, queryString);
      if (queryString != null && queryString.length() > 0) {
        uri.append('?');
        uri.append(encodeUriQuery(queryString));
      }

      if (doSendUrlFragment && fragment != null) {
        uri.append('#');
        uri.append(encodeUriQuery(fragment));
      }
      return uri.toString();
    }

    protected String rewriteQueryStringFromRequest(HttpServletRequest servletRequest, String queryString) {
      return queryString;
    }

    /** For a redirect response from the target server, this translates {@code theUrl} to redirect to
     * and translates it to one the original client can use. */
    protected String rewriteUrlFromResponse(HttpServletRequest servletRequest, String theUrl) {
      //TODO document example paths
      Route r = getTargetUri(servletRequest);
      final String targetUri = r.getDestination();
      if (theUrl.startsWith(targetUri)) {
        /*-
         * The URL points back to the back-end server.
         * Instead of returning it verbatim we replace the target path with our
         * source path in a way that should instruct the original client to
         * request the URL pointed through this Proxy.
         * We do this by taking the current request and rewriting the path part
         * using this servlet's absolute path and the path from the returned URL
         * after the base target URL.
         */
        StringBuffer curUrl = servletRequest.getRequestURL();//no query
        int pos;
        // Skip the protocol part
        if ((pos = curUrl.indexOf("://"))>=0) {
          // Skip the authority part
          // + 3 to skip the separator between protocol and authority
          if ((pos = curUrl.indexOf("/", pos + 3)) >=0) {
            // Trim everything after the authority part.
            curUrl.setLength(pos);
          }
        }
        // Context path starts with a / if it is not blank
        curUrl.append(servletRequest.getContextPath());
        // Servlet path starts with a / if it is not blank
        curUrl.append(servletRequest.getServletPath());
        curUrl.append(theUrl, targetUri.length(), theUrl.length());
        theUrl = curUrl.toString();
      }
      return theUrl;
    }

    /** The target URI as configured. Not null. */
    public Route getTargetUri(HttpServletRequest servletRequest) {
        return this.routes.stream().filter(r -> servletRequest.getRequestURI().startsWith(r.getRegexp())).findFirst().orElse(null);
    }
    
    public HttpHost getTargetHost(HttpServletRequest servletRequest){
        return this.routes.stream().filter(r -> servletRequest.getRequestURI().startsWith(r.getRegexp())).findFirst().orElse(null).getTargetHost();
    }
    /**
     * Encodes characters in the query or fragment part of the URI.
     *
     * <p>Unfortunately, an incoming URI sometimes has characters disallowed by the spec.  HttpClient
     * insists that the outgoing proxied request has a valid URI because it uses Java's {@link URI}.
     * To be more forgiving, we must escape the problematic characters.  See the URI class for the
     * spec.
     *
     * @param in example: name=value&amp;foo=bar#fragment
     */
    protected static CharSequence encodeUriQuery(CharSequence in) {
      //Note that I can't simply use URI.java to encode because it will escape pre-existing escaped things.
      StringBuilder outBuf = null;
      Formatter formatter = null;
      for(int i = 0; i < in.length(); i++) {
        char c = in.charAt(i);
        boolean escape = true;
        if (c < 128) {
          if (asciiQueryChars.get((int)c)) {
            escape = false;
          }
        } else if (!Character.isISOControl(c) && !Character.isSpaceChar(c)) {//not-ascii
          escape = false;
        }
        if (!escape) {
          if (outBuf != null)
            outBuf.append(c);
        } else {
          //escape
          if (outBuf == null) {
            outBuf = new StringBuilder(in.length() + 5*3);
            outBuf.append(in,0,i);
            formatter = new Formatter(outBuf);
          }
          //leading %, 0 padded, width 2, capital hex
          formatter.format("%%%02X",(int)c);//TODO
        }
      }
      return outBuf != null ? outBuf : in;
    }

    protected static final BitSet asciiQueryChars;
    static {
      char[] c_unreserved = "_-!.~'()*".toCharArray();//plus alphanum
      char[] c_punct = ",;:$&+=".toCharArray();
      char[] c_reserved = "?/[]@".toCharArray();//plus punct

      asciiQueryChars = new BitSet(128);
      for(char c = 'a'; c <= 'z'; c++) asciiQueryChars.set((int)c);
      for(char c = 'A'; c <= 'Z'; c++) asciiQueryChars.set((int)c);
      for(char c = '0'; c <= '9'; c++) asciiQueryChars.set((int)c);
      for(char c : c_unreserved) asciiQueryChars.set((int)c);
      for(char c : c_punct) asciiQueryChars.set((int)c);
      for(char c : c_reserved) asciiQueryChars.set((int)c);

      asciiQueryChars.set((int)'%');//leave existing percent escapes in place
    }
}