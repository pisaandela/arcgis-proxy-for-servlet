package com.paodingsoft.gis.proxy.servlet;

/**
 * Token container class.
 * Stores value of the token and a flag indicating if it was provided by the client or not.
 * @author Christopher C. Perry &lt;perrych2@msu.edu&gt;
 */

public class Token {
  private final boolean _clientToken;
  private final String _token;

  /**
   * Constructs a new token object with the specified token and client flag values.
   * @param token The token value
   * @param isClientToken Flag indicating if token was specified by client request.
   */
  public Token(String token, boolean isClientToken)
  {
    _token = token;
    _clientToken = isClientToken;
  }
  
  /**
   * Flag indicating if token was provided by the client
   * @return true if the token was provided by the client, false if it was provided by the proxy configuration.
   */
  public boolean isClientToken()
  {
    return _clientToken;
  }
 
  /**
   * Gets the client token.
   * @return A String representing the client token.
   */
  public String token()
  {
    return _token;
  }
  
}
