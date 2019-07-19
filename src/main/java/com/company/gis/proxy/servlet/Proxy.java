package com.company.gis.proxy.servlet;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Reader;

import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;

import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import java.util.concurrent.ConcurrentHashMap;

import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * @author Christopher C. Perry &lt;perrych2@msu.edu&gt;
 * ported from https://github.com/Esri/resource-proxy
 */
public class Proxy extends HttpServlet {
    private String PROXY_REFERER = Constants.DEFAULT_PROXY_REFERER;
    private static final int CLEAN_RATEMAP_AFTER = 10000;
    private static final Object _lockobject = new Object();
    private static final Logger logger = Logger.getLogger(Proxy.class.getName());

    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code> methods.
     *
     * @param request  servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException      if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType(Constants.CONTENT_TYPE_HTML);
        String uri = null;
        try (PrintWriter out = response.getWriter()) {
            ServerUrl serverUrl;
            try {
// FAIL if empty/missing URL
// BYPASS if ping command, send a ping
                if ((uri = getUri(request, response)) == null ||
                        !validateReferer(request, response) ||
                        (serverUrl = getServerUrl(response, uri)) == null ||
                        rateLimitReached(serverUrl, request, response)
                ) {
                    return;
                }

            } catch (IllegalStateException e) {
                _log(Level.WARNING, uri == null ? Constants.MSG_INVALID_URI : Constants.MSG_UNSUPPORTED_SERVICE + uri);
                sendURLMismatchError(response, uri);
                return;
            }

            Token token = initToken(serverUrl, uri, request);
            byte[] postBody = readRequestPostBody(request);

            //forwarding original request
            HttpURLConnection con;
            con = forwardToServer(request, addTokenToUri(uri, token), postBody);
            //passing header info from request to connection
            passHeadersInfo(request, con);

            if (token == null || token.isClientToken()) {
                //if token is not required or provided by the client, just fetch the response as is:
                fetchAndPassBackToClient(con, response, true);
            } else {
                //credentials for secured service have come from configuration file:
                //it means that the proxy is responsible for making sure they were properly applied:

                //first attempt to send the request:
                boolean tokenRequired = fetchAndPassBackToClient(con, response, false);

                //checking if previously used token has expired and needs to be renewed
                if (tokenRequired) {
                    _log(Level.INFO, Constants.MSG_TOKENRENEW);
                    //server returned error - potential cause: token has expired.
                    //we'll do second attempt to call the server with renewed token:
                    token = getNewTokenIfCredentialsAreSpecified(serverUrl, uri);
                    con = forwardToServer(request, addTokenToUri(uri, token), postBody);
                    passHeadersInfo(request, con); //passing header info from request to connection

                    // storing the token in Application scope, to do not waste time on
                    // requesting new one until it expires or the app is restarted.
                    synchronized (this) {
                        getServletContext().setAttribute(Constants.ATR_TOKENPREFIX + serverUrl.getUrl(), token);
                    }

                    fetchAndPassBackToClient(con, response, true);
                }
            }
        } catch (FileNotFoundException e) {
            try {
                _log(Constants.MSG_NOTFOUND, e);
                response.sendError(404, e.getLocalizedMessage() + Constants.MSG_NOTFOUNDSUFFIX);
            } catch (IOException finalErr) {
                _log(Constants.MSG_ERRORNORETRY, finalErr);
            }
        } catch (IOException e) {
            try {
                _log(Constants.MSG_FATALPROXYERROR, e);
                response.sendError(500, e.getLocalizedMessage());
            } catch (IOException finalErr) {
                _log(Constants.MSG_ERRORNORETRY, finalErr);
            }
        }
    }

    private String getUri(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String returnvalue = null;
        String uriarg = request.getQueryString();
        if (uriarg == null || uriarg.isEmpty()) {
            String errorMessage = Constants.MSG_NOEMPTYPARAMS;
            _log(Level.WARNING, errorMessage);
            sendErrorResponse(response, errorMessage, Constants.MSG_400PREFIX, HttpServletResponse.SC_BAD_REQUEST);
        } else if (uriarg.equalsIgnoreCase(Constants.CMD_PING)) {
            String checkConfig = (getConfig().canReadProxyConfig() == true) ?
                    Constants.MSG_OK : Constants.MSG_NOTREADABLE;
            String checkLog = (okToLog() == true) ? Constants.MSG_OK : Constants.MSG_DOESNTEXIST;
            sendPingMessage(response, Constants.VERSION, checkConfig, checkLog);
        } else if
        (
                uriarg.toLowerCase().startsWith(Constants.ENCODED_HTTP) ||
                        uriarg.toLowerCase().startsWith(Constants.ENCODED_HTTPS)
        ) {
            returnvalue = URLDecoder.decode(uriarg, Constants.ENCODING_UTF8);
        } else {
            returnvalue = uriarg;
        }
        return returnvalue;
    }


    private boolean validateReferer(HttpServletRequest request, HttpServletResponse response) throws IOException {
        boolean returnvalue = true;
        String[] allowedReferers = getConfig().getAllowedReferers();
        if (allowedReferers != null && allowedReferers.length > 0 && request.getHeader(Constants.ATR_REFERER) != null) {
            setReferer(request.getHeader(Constants.ATR_REFERER)); //replace PROXY_REFERER with real proxy
            String hostReferer = request.getHeader(Constants.ATR_REFERER);
            try {
                hostReferer = new URL(request.getHeader(Constants.ATR_REFERER)).getHost();
                if (!checkReferer(allowedReferers, hostReferer)) {
                    _log(Level.WARNING, Constants.MSG_UNKNOWN_REFERER + request.getHeader(Constants.ATR_REFERER));
                    sendErrorResponse(response,
                            Constants.MSG_UNSUPPORTED_REFERER,
                            Constants.MSG_ACCESS_DENIED,
                            HttpServletResponse.SC_FORBIDDEN);
                    returnvalue = false;
                }
            } catch (Exception e) {
                _log(Level.WARNING, Constants.MSG_INVALID_REFERER + request.getHeader(Constants.ATR_REFERER));
                sendErrorResponse(response,
                        Constants.MSG_VERIFY_REF_FAIL,
                        Constants.MSG_ACCESS_DENIED,
                        HttpServletResponse.SC_FORBIDDEN);
                returnvalue = false;
            }
        }

        //Check to see if allowed referer list is specified and reject if referer is null
        if (request.getHeader(Constants.ATR_REFERER) == null &&
                allowedReferers != null &&
                !allowedReferers[0].equals("*")) {
            _log(Level.WARNING, Constants.MSG_NULL_REFERER);
            sendErrorResponse(response,
                    Constants.MSG_MISSING_REFERER,
                    Constants.MSG_ACCESS_DENIED,
                    HttpServletResponse.SC_FORBIDDEN);
            returnvalue = false;
        }
        return returnvalue;
    }

    private ServerUrl getServerUrl(HttpServletResponse response, String uri) throws IOException {
        ServerUrl returnvalue = getConfig().getConfigServerUrl(uri);
        if (returnvalue == null) {
            //if no serverUrl found, send error message and get out.
            sendURLMismatchError(response, uri);
        }
        return returnvalue;
    }

    private boolean rateLimitReached(ServerUrl serverUrl, HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        //Throttling: checking the rate limit coming from particular referrer
        boolean returnvalue = false;
        if (serverUrl.getRateLimit() > -1) {
            synchronized (_lockobject) {
                ConcurrentHashMap<String, RateMeter> ratemap =
                        (ConcurrentHashMap<String, RateMeter>) getServletContext().getAttribute(Constants.ATR_RATEMAP);
                if (ratemap == null) {
                    ratemap = new ConcurrentHashMap<>();
                    getServletContext().setAttribute(Constants.ATR_RATEMAP, ratemap);
                    getServletContext().setAttribute(Constants.ATR_RATEMAPCC, 0);
                }

                String key = "[" + serverUrl.getUrl() + "]x[" + request.getRemoteAddr() + "]";
                RateMeter rate = ratemap.get(key);
                if (rate == null) {
                    rate = new RateMeter(serverUrl.getRateLimit(), serverUrl.getRateLimitPeriod());
                    RateMeter rateCheck = ratemap.putIfAbsent(key, rate);
                    if (rateCheck != null) {
                        rate = rateCheck;
                    }
                }
                if (!rate.click()) {
                    _log(Level.WARNING,
                            String.format(Constants.MSG_RATELIMIT, key, serverUrl.getRateLimit(), serverUrl.getRateLimitPeriod()));

                    sendErrorResponse(response, Constants.MSG_OVERLIMIT_DETAIL, Constants.MSG_OVERLIMIT, 429);
                    returnvalue = true;
                } else {
                    //making sure the rateMap gets periodically cleaned up so it does not grow uncontrollably
                    int cnt = (Integer) getServletContext().getAttribute(Constants.ATR_RATEMAPCC);
                    cnt++;
                    if (cnt >= CLEAN_RATEMAP_AFTER) {
                        cnt = 0;
                        cleanUpRatemap(ratemap);
                    }
                    getServletContext().setAttribute(Constants.ATR_RATEMAPCC, cnt);
                }
            }
        }
        return returnvalue;
    }

    public Token initToken(ServerUrl serverUrl, String uri, HttpServletRequest request)
            throws IOException {
        Token returnvalue = null;

        String tokenvalue;
        //if token comes with client request, it takes precedence over token or credentials stored in configuration
        boolean hasClientToken = ((tokenvalue = request.getParameter("token")) != null);

        if (!hasClientToken) {
            // Get new token and append to the request.
            // But first, look up in the application scope, maybe it's already there:
            tokenvalue = (String) getServletContext().getAttribute(Constants.ATR_TOKENPREFIX + serverUrl.getUrl());
            boolean tokenIsInApplicationScope = returnvalue != null && !tokenvalue.isEmpty();

            //if still no token, let's see if there are credentials stored in configuration which we can use to obtain new token
            if (!tokenIsInApplicationScope) {
                tokenvalue = getNewTokenIfCredentialsAreSpecified(serverUrl, uri).token();
            }

            if (tokenvalue != null && !tokenvalue.isEmpty() && !tokenIsInApplicationScope) {
                // storing the token in Application scope, to do not waste time on
                // requesting new one until it expires or the app is restarted.
                getServletContext().setAttribute(Constants.ATR_TOKENPREFIX + serverUrl.getUrl(), returnvalue);
            }
        }
        if (tokenvalue != null && !tokenvalue.isEmpty()) {
            returnvalue = new Token(tokenvalue, hasClientToken);
        }
        return returnvalue;
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">

    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request  servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException      if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request  servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException      if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>


    //setReferer if real referer exist
    private void setReferer(String r) {
        PROXY_REFERER = r;
    }

    private byte[] readRequestPostBody(HttpServletRequest request) throws IOException {
        int clength = request.getContentLength();
        if (clength > 0) {
            byte[] bytes = new byte[clength];
            try (DataInputStream dataIs = new DataInputStream(request.getInputStream())) {
                dataIs.readFully(bytes);
            }
            return bytes;
        }

        return new byte[0];
    }

    private HttpURLConnection forwardToServer(HttpServletRequest request, String uri, byte[] postBody) throws IOException {
        return postBody.length > 0 ?
                doHTTPRequest(uri,
                        postBody,
                        Constants.METHOD_POST,
                        request.getHeader(Constants.ATR_REFERER),
                        request.getContentType()) :
                doHTTPRequest(uri, request.getMethod());
    }

    private boolean fetchAndPassBackToClient(HttpURLConnection con,
                                             HttpServletResponse clientResponse,
                                             boolean ignoreAuthenticationErrors)
            throws IOException {
        if (con != null) {
            Map<String, List<String>> headerFields = con.getHeaderFields();

            Set<String> headerFieldsSet = headerFields.keySet();
            Iterator<String> hearerFieldsIter = headerFieldsSet.iterator();

            while (hearerFieldsIter.hasNext()) {
                String headerFieldKey = hearerFieldsIter.next();
                List<String> headerFieldValue = headerFields.get(headerFieldKey);
                StringBuilder sb = new StringBuilder();
                for (String value : headerFieldValue) {
                    sb.append(value);
                    sb.append("");
                }
                if (headerFieldKey != null) {
                    clientResponse.addHeader(headerFieldKey, sb.toString());
                }
            }

            InputStream byteStream;
            if (con.getResponseCode() >= HttpServletResponse.SC_BAD_REQUEST && con.getErrorStream() != null) {
                if (ignoreAuthenticationErrors &&
                        (
                                con.getResponseCode() == Constants.CODE_TOKEN_EXPIRED ||
                                        con.getResponseCode() == Constants.CODE_CLIENT_CLOSED_REQUEST
                        )
                ) {
                    return true;
                }
                byteStream = con.getErrorStream();
            } else {
                byteStream = con.getInputStream();
            }

            clientResponse.setStatus(con.getResponseCode());

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();

            byte[] bytes = new byte[Constants.INPUT_BUFFER_BYTES];
            int bytesRead;

            while ((bytesRead = byteStream.read(bytes, 0, Constants.INPUT_BUFFER_BYTES)) > 0) {
                buffer.write(bytes, 0, bytesRead);
            }
            buffer.flush();

            byte[] byteResponse = buffer.toByteArray();
            try (OutputStream ostream = clientResponse.getOutputStream()) {
                ostream.write(byteResponse);
            }
            byteStream.close();
        }
        return false;
    }

    private boolean passHeadersInfo(HttpServletRequest request, HttpURLConnection con) {
        Enumeration headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String key = (String) headerNames.nextElement();
            String value = request.getHeader(key);
            if (!key.equalsIgnoreCase(Constants.ATR_HOST)) {
                con.setRequestProperty(key, value);
            }
        }
        return true;
    }

    private HttpURLConnection doHTTPRequest(String uri, String method) throws IOException {
        byte[] bytes = null;
        String contentType = null;
        if (method.equals(Constants.METHOD_POST)) {
            // TODO:  AARRGGGHH, Nooooo!
            String[] uriArray = uri.split("\\?");

            if (uriArray.length > 1) {
                contentType = Constants.CONTENT_TYPE_URLENCODEDFORM;
                String queryString = uriArray[1];

                bytes = URLEncoder.encode(queryString, Constants.ENCODING_UTF8).getBytes();
            }
        }
        return doHTTPRequest(uri, bytes, method, PROXY_REFERER, contentType);
    }

    private HttpURLConnection doHTTPRequest(String uri,
                                            byte[] bytes,
                                            String method,
                                            String referer,
                                            String contentType) throws IOException {
        URL url = new URL(uri);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setConnectTimeout(5000);
        con.setReadTimeout(10000);

        con.setRequestProperty(Constants.ATR_REFERER, referer);
        con.setRequestMethod(method);

        if (bytes != null && bytes.length > 0 || method.equals(Constants.METHOD_POST)) {
            if (bytes == null) {
                bytes = new byte[0];
            }

            con.setRequestMethod(Constants.METHOD_POST);
            con.setDoOutput(true);
            if (contentType == null || contentType.isEmpty()) {
                contentType = Constants.CONTENT_TYPE_URLENCODEDFORM;
            }

            con.setRequestProperty(Constants.ATR_CONTENT_TYPE, contentType);

            OutputStream os = con.getOutputStream();
            os.write(bytes);
        }
        return con;
    }

    private String webResponseToString(HttpURLConnection con) throws IOException {
        InputStream in = con.getInputStream();

        StringBuilder content = new StringBuilder();
        try (Reader reader = new BufferedReader(new InputStreamReader(in, Constants.ENCODING_UTF8))) {
            char[] buffer = new char[5000];
            int n;

            while ((n = reader.read(buffer)) != -1) {
                content.append(buffer, 0, n);
            }
        }

        String strResponse = content.toString();

        return strResponse;
    }

    private Token getNewTokenIfCredentialsAreSpecified(ServerUrl su, String url) throws IOException {
        Token token = null;
        String tokenstring;
        boolean isUserLogin = (su.getUsername() != null && !su.getUsername().isEmpty()) &&
                (su.getPassword() != null && !su.getPassword().isEmpty());
        boolean isAppLogin = (su.getClientId() != null && !su.getClientId().isEmpty()) &&
                (su.getClientSecret() != null && !su.getClientSecret().isEmpty());
        if (isUserLogin || isAppLogin) {
            _log(Level.INFO, Constants.MSG_CRED_FOUND_IN_CONF + isAppLogin);
            if (isAppLogin) {
                //OAuth 2.0 mode authentication
                //"App Login" - authenticating using client_id and client_secret stored in config
                if (su.getOAuth2Endpoint() == null || su.getOAuth2Endpoint().isEmpty()) {
                    su.setOAuth2Endpoint(Constants.DEFAULT_OAUTH);
                }
                // TODO: This code looks suspect
                if (su.getOAuth2Endpoint().charAt(su.getOAuth2Endpoint().length() - 1) != '/') {
                    su.setOAuth2Endpoint(su.getOAuth2Endpoint() + "/");
                }

                _log(Level.INFO, String.format(Constants.MSG_SERVICE_SECURED_BY, su.getOAuth2Endpoint()));
                String uri = String.format(Constants.URL_OAUTH, su.getOAuth2Endpoint(), su.getClientId(), su.getClientSecret());
                //TODO:  Is this uri sanitized?
                String tokenResponse = webResponseToString(doHTTPRequest(uri, Constants.METHOD_POST));
                tokenstring = extractToken(tokenResponse, Constants.KEY_ACCESS_TOKEN);
                if (tokenstring != null && !tokenstring.isEmpty()) {
                    tokenstring = exchangePortalTokenForServerToken(tokenstring, su);
                }
            } else // User login
            {
                //standalone ArcGIS Server token-based authentication

                //if a request is already being made to generate a token, just let it go
                if (url.toLowerCase().contains("/" + Constants.PATH_GENERATE_TOKEN)) {
                    String tokenResponse = webResponseToString(doHTTPRequest(url, Constants.METHOD_POST));
                    tokenstring = extractToken(tokenResponse, Constants.KEY_TOKEN);
                    return token;
                } else {
                    String infoUrl = "";
                    //lets look for '/rest/' in the request url (could be 'rest/services', 'rest/community'...)
                    //TODO:  MORE ICKKY!!!
                    if (url.toLowerCase().contains("/" + Constants.PATH_REST)) {
                        infoUrl = url.substring(0, url.indexOf("/" + Constants.PATH_REST + "/"));
                        infoUrl += "/" + Constants.PATH_REST + "/" + Constants.PATH_INFO;
                        //if we don't find 'rest', lets look for the portal specific 'sharing' instead
                    } else if (url.toLowerCase().contains("/" + Constants.PATH_SHARING + "/")) {
                        infoUrl = url.substring(0, url.indexOf(Constants.PATH_SHARING));
                        infoUrl += "/" + Constants.PATH_SHARING + "/" + Constants.PATH_REST + "/" + Constants.PATH_INFO;
                    } else {
                        return new Token("-1", isUserLogin); //return -1, signaling that infourl can not be found
                    }

                    if (infoUrl != "") {
                        _log(Level.INFO, Constants.MSG_QUERYING_SEC_ENDPOINT);

                        String tokenServiceUri = su.getTokenServiceUri();

                        if (tokenServiceUri == null || tokenServiceUri.isEmpty()) {
                            _log(Level.INFO, Constants.TOKEN_URL_NOT_CACHED);
                            String infoResponse = webResponseToString(doHTTPRequest(infoUrl, Constants.METHOD_GET));
                            tokenServiceUri = getJsonValue(infoResponse, Constants.KEY_TOKENSERVICESURL);
                            su.setTokenServiceUri(tokenServiceUri);
                        }

                        if (tokenServiceUri != null & !tokenServiceUri.isEmpty()) {
                            _log(Level.INFO, Constants.MSG_SERVICE_SECURED_BY);
                            // TODO: Sanitize parameters
                            String uri = String.format(Constants.URL_TOKEN_SERVICE_REQUEST,
                                    tokenServiceUri,
                                    PROXY_REFERER,
                                    su.getUsername(),
                                    su.getPassword());
                            String tokenResponse = webResponseToString(doHTTPRequest(uri, Constants.METHOD_POST));
                            token = new Token(extractToken(tokenResponse, Constants.KEY_TOKEN), isUserLogin);
                        }
                    }
                }
            }
        }
        return token;
    }

    private boolean checkReferer(String[] allowedReferers, String referer) {
        if (allowedReferers != null && allowedReferers.length > 0) {
            if (allowedReferers.length == 1 && allowedReferers[0].equals("*")) return true; //speed-up
            for (String allowedReferer : allowedReferers) {
                allowedReferer = allowedReferer.replaceAll("\\s", "");
                if (referer.toLowerCase().equals(allowedReferer.toLowerCase())) {
                    return true;
                } else if (allowedReferer.contains("*")) { //try if the allowed referer contains wildcard for subdomain
                    if (checkWildcardSubdomain(allowedReferer, referer)) {
                        return true; //return true if match wildcard subdomain
                    }
                }
            }
            return false;//no-match
        }
        return true;//when allowedReferer is null, then allow everything
    }


    private boolean checkWildcardSubdomain(String allowedReferer, String referer) {
        String[] allowedRefererParts = allowedReferer.split("(\\.)");
        String[] refererParts = referer.split("(\\.)");

        int allowedIndex = allowedRefererParts.length - 1;
        int refererIndex = refererParts.length - 1;
        while (allowedIndex >= 0 && refererIndex >= 0) {
            if (allowedRefererParts[allowedIndex].equalsIgnoreCase(refererParts[refererIndex])) {
                allowedIndex = allowedIndex - 1;
                refererIndex = refererIndex - 1;
            } else {
                if (allowedRefererParts[allowedIndex].equals("*")) {
                    allowedIndex = allowedIndex - 1;
                    refererIndex = refererIndex - 1;
                    continue; //next
                }
                return false;
            }
        }
        return true;
    }

    private String getFullUrl(String url) {
        return url.startsWith("//") ? url.replace("//", Constants.PROTO_HTTPS + "://") : url;
    }

    private String exchangePortalTokenForServerToken(String portalToken, ServerUrl su) throws IOException {
        String url = getFullUrl(su.getUrl());
        _log(Level.INFO, String.format(Constants.MSG_TOKEN_EXCHANGE, url));
        String oa2end = su.getOAuth2Endpoint();
        String uri = String.format(
                Constants.PATH_TOKEN_EXCHANGE,
                oa2end.substring(0, oa2end.toLowerCase().indexOf("/" + Constants.PATH_OAUTH2 + "/")),
                portalToken,
                url);
        String tokenResponse = webResponseToString(doHTTPRequest(uri, Constants.METHOD_GET));
        return extractToken(tokenResponse, Constants.KEY_TOKEN);
    }

    private String addTokenToUri(String uri, Token token) {
        if (token != null) {
            // TODO:  BLEECCHH!  There has to be a better way...
            uri += (uri.contains("?") ? "&" : "?") + Constants.KEY_TOKEN + "=" + token.token();
        }
        return uri;
    }

    private String extractToken(String tokenResponse, String key) {
        String token = getJsonValue(tokenResponse, key);
        if (token == null || token.isEmpty()) {
            _log(Level.WARNING, Constants.MSG_CANNOTGETTOKEN + tokenResponse);
        } else {
            _log(Level.INFO, Constants.MSG_TOKENOBTAINED + token);
        }
        return token;
    }

    private String getJsonValue(String text, String key) {
        _log(Level.FINE, Constants.MSG_JSON_RESPONSE + text);
        int i = text.indexOf(key);
        String value = "";
        if (i > -1) {
            value = text.substring(text.indexOf(':', i) + 1).trim();
            value = (value.length() > 0 && value.charAt(0) == '"') ?
                    value.substring(1, value.indexOf('"', 1)) :
                    value.substring(0, Math.max(0, Math.min(Math.min(value.indexOf(","), value.indexOf("]")), value.indexOf("}"))));
        }
        _log(Level.FINE, Constants.MSG_EXTRACTED_VALUE + value);
        return value;
    }

    private void cleanUpRatemap(ConcurrentHashMap<String, RateMeter> ratemap) {
        Set<Map.Entry<String, RateMeter>> entrySet = ratemap.entrySet();
        for (Map.Entry<String, RateMeter> entry : entrySet) {
            RateMeter rate = entry.getValue();
            if (rate.canBeCleaned()) {
                ratemap.remove(entry.getKey(), rate);
            }
        }
    }

    /**
     * Static
     */

    private static ProxyConfig getConfig() throws IOException {
        ProxyConfig config = ProxyConfig.getCurrentConfig();
        if (config != null) {
            return config;
        } else {
            throw new FileNotFoundException(Constants.MSG_CONF_NOT_FOUND);
        }
    }

    //writing Log file

    private boolean okToLog() {
        try {
            ProxyConfig proxyConfig = getConfig();
            String filename = proxyConfig.getLogFile();
            return filename != null && !filename.isEmpty() && logger != null;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private static void _log(Level level, String s, Throwable thrown) {
        try {
            ProxyConfig proxyConfig = getConfig();
            String filename = proxyConfig.getLogFile();
            boolean okToLog = filename != null && !filename.isEmpty() && logger != null;
            synchronized (_lockobject) {
                if (okToLog) {
                    if (logger.getUseParentHandlers()) {
                        FileHandler fh = new FileHandler(filename, true);
                        logger.addHandler(fh);
                        SimpleFormatter formatter = new SimpleFormatter();
                        fh.setFormatter(formatter);
                        logger.setUseParentHandlers(false);

                        String logLevelStr = proxyConfig.getLogLevel();
                        Level logLevel = Level.SEVERE;

                        if (logLevelStr != null) {
                            try {
                                logLevel = Level.parse(logLevelStr);
                            } catch (IllegalArgumentException e) {
                                SimpleDateFormat dt = new SimpleDateFormat(Constants.DATE_FORMAT);
                                System.err.println(
                                        String.format(Constants.MSG_INVALID_LOG_LEVEL, dt.format(new Date()), logLevelStr)
                                );
                            }
                        }
                        logger.setLevel(logLevel);

                        logger.info("Log handler configured and initialized.");
                    }

                    if (thrown != null) {
                        logger.log(level, s, thrown);
                    } else {
                        logger.log(level, s);
                    }
                }
            }
        } catch (Exception e) {
            SimpleDateFormat dt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            System.err.println("Error writing to log: ");
            System.err.println(dt.format(new Date()) + " " + s);
            e.printStackTrace();
        }
    }

    private static void _log(String s, Throwable thrown) {
        _log(Level.SEVERE, s, thrown);
    }

    private static void _log(Level level, String s) {
        _log(level, s, null);
    }


    private static void sendErrorResponse(HttpServletResponse response, String errorDetails, String errorMessage, int errorCode)
            throws IOException {
        response.setHeader("Content-Type", "application/json");
        String message = "{" +
                "\"error\": {" +
                "\"code\": " + errorCode + "," +
                "\"details\": [" +
                "\"" + errorDetails + "\"" +
                "], \"message\": \"" + errorMessage + "\"}}";

        response.setStatus(errorCode);
        OutputStream output = response.getOutputStream();

        output.write(message.getBytes());

        output.flush();
    }

    private static void sendURLMismatchError(HttpServletResponse response, String attemptedUri)
            throws IOException {
        sendErrorResponse(response,
                "Proxy has not been set up for this URL. Make sure there is a serverUrl in the "
                        + "configuration file that matches: " + attemptedUri,
                "Proxy has not been set up for this URL.",
                HttpServletResponse.SC_FORBIDDEN);
    }

    private static void sendPingMessage(HttpServletResponse response, String version, String config, String log)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader("Content-Type", "application/json");
        String message = "{ " +
                "\"Proxy Version\": \"" + version + "\"" +
                //", \"Java Version\": \"" + System.getProperty("java.version") + "\"" +
                ", \"Configuration File\": \"" + config + "\"" +
                ", \"Log File\": \"" + log + "\"" +
                "}";
        OutputStream output = response.getOutputStream();
        output.write(message.getBytes());
        output.flush();
    }
}
