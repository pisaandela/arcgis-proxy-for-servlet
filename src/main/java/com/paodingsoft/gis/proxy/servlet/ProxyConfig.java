package com.paodingsoft.gis.proxy.servlet;
import org.apache.commons.lang3.StringUtils;

import java.io.InputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.ArrayList;

/**
 *
 * @author Christopher C. Perry &lt;perrych2@msu.edu&gt;
 * ported from https://github.com/Esri/resource-proxy
 */
public class ProxyConfig {
  public boolean canReadProxyConfig(){
    InputStream configFile = ProxyConfig.class.getClassLoader().getResourceAsStream("proxy.config");
    return configFile != null;
  }

  public synchronized static ProxyConfig loadProxyConfig()  throws IOException{
    ProxyConfig config = null;
    InputStream configFile = ProxyConfig.class.getClassLoader().getResourceAsStream("proxy.config");
    if (configFile != null) {
      BufferedReader reader = new BufferedReader( new InputStreamReader (configFile, "UTF-8"));
      String line;
      StringBuilder stringBuilder = new StringBuilder();

      while( ( line = reader.readLine() ) != null ) {
        stringBuilder.append( line );
      }

      String configFileStr = stringBuilder.toString();
      configFileStr = configFileStr.replaceAll("(?ms)<!\\-\\-(.+?)\\-\\->", "");

      Pattern p = Pattern.compile("<\\s*ProxyConfig(.+?)>", Pattern.MULTILINE | Pattern.DOTALL);
      Matcher m = p.matcher(configFileStr);
      boolean found = m.find();

      if (found){

        String proxyConfigAttributes = m.group(1);

        config = new ProxyConfig();

        if (proxyConfigAttributes != null && !StringUtils.isEmpty(proxyConfigAttributes)){
          String mustMatch = ProxyConfig.getAttributeWithRegex("mustMatch", proxyConfigAttributes);
          if (mustMatch != null && !StringUtils.isEmpty(mustMatch)){
            config.setMustMatch(Boolean.parseBoolean(mustMatch));
          }

          String allowedReferers = ProxyConfig.getAttributeWithRegex("allowedReferers", proxyConfigAttributes);
          if (allowedReferers != null && !StringUtils.isEmpty(allowedReferers)){
            config.setAllowedReferers(allowedReferers.split(","));
          }

          String logFile = ProxyConfig.getAttributeWithRegex("logFile", proxyConfigAttributes);
          if (logFile != null && !StringUtils.isEmpty(logFile)){
            config.setLogFile(logFile);
          }

          String logLevel = ProxyConfig.getAttributeWithRegex("logLevel", proxyConfigAttributes);
          if (logLevel != null && !StringUtils.isEmpty(logLevel)){
            config.setLogLevel(logLevel);
          }


          p = Pattern.compile("<\\s*serverUrls\\s*>(.+?)<\\s*/\\s*serverUrls\\s*>", Pattern.MULTILINE | Pattern.DOTALL);
          m = p.matcher(configFileStr);
          found = m.find();

          if (found) {
            String serverUrls = m.group(1);
            if (serverUrls != null && !StringUtils.isEmpty(serverUrls)) {
              p = Pattern.compile("<\\s*serverUrl (.+?)((<\\s*/\\s*serverUrl\\s*)|/)>", Pattern.MULTILINE | Pattern.DOTALL);
              m = p.matcher(serverUrls);

              ArrayList<ServerUrl> serverList = new ArrayList<ServerUrl>();
              while(m.find()){
                String server = m.group(1);
                String url = ProxyConfig.getAttributeWithRegex("url", server);
                String matchAll = ProxyConfig.getAttributeWithRegex("matchAll", server);
                String oauth2Endpoint = ProxyConfig.getAttributeWithRegex("oauth2Endpoint", server);
                String username = ProxyConfig.getAttributeWithRegex("username", server);
                String password = ProxyConfig.getAttributeWithRegex("password", server);
                String clientId = ProxyConfig.getAttributeWithRegex("clientId", server);
                String clientSecret = ProxyConfig.getAttributeWithRegex("clientSecret", server);
                String rateLimit = ProxyConfig.getAttributeWithRegex("rateLimit", server);
                String rateLimitPeriod = ProxyConfig.getAttributeWithRegex("rateLimitPeriod", server);
                String tokenServiceUri = ProxyConfig.getAttributeWithRegex("tokenServiceUri", server);

                serverList.add(new ServerUrl(url, matchAll, oauth2Endpoint, username, password, clientId, clientSecret, rateLimit, rateLimitPeriod, tokenServiceUri));
              }

              config.setServerUrls(serverList.toArray(new ServerUrl[serverList.size()]));
            }
          }
        }
      }
    }
    return config;
  }

  private static String getAttributeWithRegex(String property, String tag){
    Pattern p = Pattern.compile(property + "=\\s*\"\\s*(.+?)\\s*\"");
    Matcher m = p.matcher(tag);
    boolean found = m.find();
    String match = null;
    if (found){
      match = m.group(1);
    }
    return match;
  }

  private static ProxyConfig appConfig;

  public static ProxyConfig getCurrentConfig() throws IOException{
    ProxyConfig config = appConfig;
    if (config == null) {
      config = loadProxyConfig();
      if (config != null) {
        appConfig = config;
      }
    }
    return config;
  }

  ServerUrl[] serverUrls;
  boolean mustMatch;
  String logFile;
  String logLevel;
  String[] allowedReferers;

  public ServerUrl[] getServerUrls() {
    return this.serverUrls;
  }
  
  public void setServerUrls(ServerUrl[] value){
    this.serverUrls = value;
  }

  public boolean getMustMatch(){
    return this.mustMatch;
  }
    
  public void setMustMatch(boolean value){
    this.mustMatch = value;
  }

  public String[] getAllowedReferers(){
    return this.allowedReferers;
  }
    
  public void setAllowedReferers(String[] value){
    this.allowedReferers = value;
  }

  public String getLogFile(){
    return this.logFile;
  }
    
  public void setLogFile(String value){
    this.logFile = value;
  }

  public String getLogLevel(){
    return this.logLevel;
  }
    
  public void setLogLevel(String value){
    this.logLevel = value;
  }

  public ServerUrl getConfigServerUrl(String uri) {
    //split request URL to compare with allowed server URLs
    String[] uriParts = uri.split("(/)|(\\?)");
    String[] configUriParts;

    for (ServerUrl su : serverUrls) {
      //if a relative path is specified in the proxy configuration file, append what's in the request itself
      if (!su.getUrl().startsWith("http"))
      {
        su.setUrl(new StringBuilder(su.getUrl()).insert(0, uriParts[0]).toString());
      }

      configUriParts = su.getUrl().split("/");

      //if the request has less parts than the config, don't allow
      if (configUriParts.length > uriParts.length)
      {
        continue;
      }

      int i;
      
      //skip comparing the protocol, so that either http or https is considered valid
      for (i = 1; i < configUriParts.length; i++)
      {
        if (!configUriParts[i].toLowerCase().equals(uriParts[i].toLowerCase()) )
        {
          break;
        }
      }
      if (i == configUriParts.length)
      {
        //if the urls don't match exactly, and the individual matchAll tag is 'false', don't allow
        if (configUriParts.length == uriParts.length || su.getMatchAll())
        {
          return su;
        }
      }
    }

    if (this.mustMatch)
    {
      return null;//if nothing match and mustMatch is true, return null
    }
    else
    {
      return new ServerUrl(uri); //if mustMatch is false send the server URL back that is the same the uri to pass thru
    }
  }

  public static boolean isUrlPrefixMatch(String prefix, String uri){
      return uri.toLowerCase().startsWith(prefix.toLowerCase()) ||
              uri.toLowerCase().replace("https://","http://").startsWith(prefix.toLowerCase()) ||
              uri.toLowerCase().substring(uri.indexOf("//")).startsWith(prefix.toLowerCase());
  }  
}
