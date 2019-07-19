package com.company.gis.proxy.servlet;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 * @author Christopher C. Perry &lt;perrych2@msu.edu&gt;
 * ported from https://github.com/Esri/resource-proxy
 */
public class ServerUrl {
  String url;
  boolean matchAll;
  String oauth2Endpoint;
  String username;
  String password;
  String clientId;
  String clientSecret;
  String rateLimit;
  String rateLimitPeriod;
  String tokenServiceUri;

  public ServerUrl( String url, 
                    String matchAll, 
                    String oauth2Endpoint, 
                    String username, 
                    String password, 
                    String clientId, 
                    String clientSecret, 
                    String rateLimit,
                    String rateLimitPeriod, 
                    String tokenServiceUri){
    this.url = url;
    this.matchAll = matchAll == null || matchAll.isEmpty() ? true : Boolean.parseBoolean(matchAll);
    this.oauth2Endpoint = oauth2Endpoint;
    this.username = username;
    this.password = password;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.rateLimit = rateLimit;
    this.rateLimitPeriod = rateLimitPeriod;
    this.tokenServiceUri = tokenServiceUri;
  }

  public ServerUrl(String url){
    this.url = url;
  }

  private static ConcurrentHashMap<String,String> tokenServiceMap = new ConcurrentHashMap<String,String>();

  public String getUrl(){
    return this.url;
  }
  
  public void setUrl(String value){
    this.url = value;
  }

  public boolean getMatchAll(){
      return this.matchAll;
  }

  public void setMatchAll(boolean value){
    this.matchAll = value;
  }

  public String getOAuth2Endpoint(){
    return this.oauth2Endpoint;
  }
  
  public void setOAuth2Endpoint(String value){
    this.oauth2Endpoint = value;
  }

  public String getUsername(){
    return this.username;
  }
  
  public void setUsername(String value){
    this.username = value;
  }

  public String getPassword(){
    return this.password;
  }

  public void setPassword(String value){
    this.password = value;
  }

  public String getClientId(){
    return this.clientId;
  }

  public void setClientId(String value){
    this.clientId = value;
  }

  public String getClientSecret(){
    return this.clientSecret;
  }

  public void setClientSecret(String value){
    this.clientSecret = value;
  }

  public int getRateLimit(){
    return (this.rateLimit == null || this.rateLimit.isEmpty() ) ? -1 : Integer.parseInt(this.rateLimit);
  }

  public void setRateLimit(int value){
    this.rateLimit = String.valueOf(value);
  }

  public int getRateLimitPeriod(){
    return (this.rateLimitPeriod == null || this.rateLimitPeriod.isEmpty() ) ? -1 : Integer.parseInt(this.rateLimitPeriod);
  }
    
  public void setRateLimitPeriod(int value){
    this.rateLimitPeriod = String.valueOf(value);
  }

  public String getTokenServiceUri(){
    if (this.tokenServiceUri == null && tokenServiceMap != null){
      this.tokenServiceUri = tokenServiceMap.get(this.url);
    }
    return this.tokenServiceUri;
  }

  public void setTokenServiceUri(String value){
    this.tokenServiceUri = value;
    tokenServiceMap.put(this.url, value);
  }  
}
