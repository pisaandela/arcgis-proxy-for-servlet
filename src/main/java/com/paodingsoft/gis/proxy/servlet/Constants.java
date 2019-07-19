/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.paodingsoft.gis.proxy.servlet;

/**
 *
 * @author Christopher C. Perry &lt;perrych2@msu.edu&gt;
 */
public class Constants {
  /** Application version identifier */
  public static final String VERSION = "1.0 Alpha";
  
  public static final String METHOD_POST = "POST";
  public static final String METHOD_GET = "GET";
  /** Default OAUTH endpoint to use */
  public static final String DEFAULT_OAUTH = "https://www.arcgis.com/sharing/oauth2/";
  
  /** Default referer (sic) */
  public static final String DEFAULT_PROXY_REFERER = "http://localhost/proxy.jsp";
  
  /** Content type string for html. */
  public static final String CONTENT_TYPE_HTML = "text/html;charset=UTF-8";
  
  public static final String CONTENT_TYPE_URLENCODEDFORM = "application/x-www-form-urlencoded";
  public static final String KEY_TOKENSERVICESURL = "tokenServicesUrl";
  public static final String URL_TOKEN_SERVICE_REQUEST = "%s$?f=json&request=getToken&referer=%s$&expiration=60&username=%s$&password=%s$";
  /** UTF-8 Encoding Parameter */
  public static final String ENCODING_UTF8 = "UTF-8";
  public static final String PATH_OAUTH2 = "oauth2";
  public static final String PATH_TOKEN_EXCHANGE = "%s$/generateToken?token=%s$&serverURL=%s$&f=json";
  public static final String ENCODED_HTTP = "http%3a%2f%2f";
  public static final String MSG_CONF_NOT_FOUND = "The proxy configuration file";
  public static final String PROTO_HTTP = "http";
  public static final String PROTO_HTTPS = "https";
  public static final String MSG_TOKEN_EXCHANGE = "[Info]: Exchanging Portal token for Server-specific token for %s$...";
  public static final String ENCODED_HTTPS = "https%3a%2f%2f";
  public static final String ATR_CONTENT_TYPE = "Content-Type";
  public static final String ATR_REFERER = "referer";
  public static final String ATR_RATEMAP = "rateMap";
  public static final String ATR_RATEMAPCC = "rateMap_cleanup_counter";
  public static final String ATR_TOKENPREFIX = "token_for_";
  public static final String ATR_HOST = "host";
  public static final String CMD_PING = "ping";
  public static final String MSG_CRED_FOUND_IN_CONF = "Matching credentials found in configuration file. OAuth 2.0 mode: ";
  public static final String KEY_ACCESS_TOKEN = "access_token";
  public static final String MSG_CANNOTGETTOKEN = "Token cannot be obtained: ";
  public static final String MSG_TOKENOBTAINED = "Token obtained: ";
  public static final String MSG_JSON_RESPONSE = "JSON Response: ";
  public static final String MSG_NULL_REFERER = "Proxy is being called by a null referer.  Access denied.";
  public static final String MSG_EXTRACTED_VALUE = "Extracted Value: ";
  
  public static final String MSG_INVALID_REFERER = "Proxy is being used from an invalid referer: ";
  
  public static final String MSG_MISSING_REFERER = "Current proxy configuration settings do not allow requests which do not include a referer header.";
  public static final String MSG_VERIFY_REF_FAIL = "Error verifying referer. ";
  public static final String MSG_UNSUPPORTED_SERVICE = "Proxy is being used for an unsupported service: ";
  public static final String MSG_INVALID_URI = "Unable to parse proxied URI.";
  public static final String MSG_ACCESS_DENIED = "403 - Forbidden: Access is denied.";
  
  public static final String MSG_UNKNOWN_REFERER = "Proxy is being used from an unknown referer: ";
  
  public static final String MSG_UNSUPPORTED_REFERER = "Unsupported referer. ";
  
  public static final String MSG_RATELIMIT = "Pair %s$ is throttled to %d$ requests per %d$ minute(s). "
                                             + "Come back later.";
  public static final String MSG_OVERLIMIT_DETAIL = "This is a metered resource, number of requests have exceeded the rate limit interval.";
  public static final String MSG_OVERLIMIT = "Error 429 - Too Many Requests";
  public static final String MSG_OK = "OK";
  public static final String MSG_TOKENRENEW = "Renewing token and trying again.";
  public static final String MSG_NOTFOUND = "404 Not Found .";
  public static final String MSG_NOTFOUNDSUFFIX = " was NOT Found.";
  public static final String MSG_NOTREADABLE = "Not Readable";
  public static final String MSG_ERRORNORETRY = "There was an error sending a response to the client.  Will not try again.";
  public static final String MSG_DOESNTEXIST = "Not Exist/Readable";
  public static final String MSG_FATALPROXYERROR = "A fatal proxy error occurred.";
  public static final String MSG_CREATING = "Creating request for ";
  
  public static final String MSG_NOEMPTYPARAMS = "This proxy does not support empty parameters.";

  public static final String MSG_400PREFIX = "400 - ";
  public static final String MSG_SERVICE_SECURED_BY = "Service is secured by %s$: getting new token...";
  
  public static final String URL_OAUTH = "%s$token?client_id=%s$&client_secret=%s$&grant_type=client_credentials&f=json";
  
  public static final int CODE_TOKEN_EXPIRED = 498;
  public static final int CODE_CLIENT_CLOSED_REQUEST = 499;
  
  public static final int INPUT_BUFFER_BYTES = 5000;
  public static final String PATH_GENERATE_TOKEN = "generatetoken";
  public static final String PATH_REST = "rest";
  public static final String PATH_INFO = "info?f=json";
  public static final String KEY_TOKEN = "token";
  public static final String PATH_SHARING = "sharing";
  public static final String MSG_QUERYING_SEC_ENDPOINT = "[Info]: Querying security endpoint...";
  public static final String TOKEN_URL_NOT_CACHED = "Token URL not cached.  Querying rest info page...";
  public static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";
  public static final String MSG_INVALID_LOG_LEVEL = "%s$: %s$ is not a valid logging level.  Defaulting to SEVERE.";
}
