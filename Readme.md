# v1.1.2版的arcgis代理servlet版(已作废)
> 没必要做servlet版，有更简单的方法，移步 https://blog.csdn.net/amingccc/article/details/127724989
## 1. 老版本存在的问题
- 官方库中没有servlet版本，只有jsp版，并不能用在分离的项目中。   
https://github.com/Esri/resource-proxy

- 别人的servlet版本比较老，且基于netbean，不能直接导入到idea或者eclipse中。     
https://github.com/Outtascope/servlet-proxy

## 2. 改造后的几个版本
> 放入tomcat中启动，我的版本是8.5.x
- servlet改造第一版，放在com.company.gis.proxy.servlet目录     
    基于servlet-proxy改造，且使用jdk8。   
    访问地址：localhost:8080/gis_proxy/demoProxy?ping
- proxy.jsp官方版，放在webapp目录。    
    因为和新的有冲突，全文件注释掉了。   
    访问地址：localhost:8080/gis_proxy/proxy.jsp?ping
- 改造好的servlet1.1.2版，基于jsp官方版，在com.company.gis.proxy.jsp目录。     
    访问地址：localhost:8080/gis_proxy/proxy?ping  

## 3. 如何加入到springboot项目
1. 拷贝proxy.config文件至resources目录下；
2. 拷贝JspServlet.java到相应目录；
2. 在Application.java文件中加入`@ServletComponentScan`的类上注解；
3. 在JspServlet.java文件中加入`@WebServlet(urlPatterns = "/proxy",name="ProxyServlet")`的类上注解；
4. 访问localhost:8080/proxy?ping，或者加上项目名的地址。
> 网上有很多springboot使用servlet的方法的文章，可以百度一下在操作。  

## 4. 问题收集
1. 忽略https证书验证的解决
    - 出现情况：     
        `javax.net.ssl.SSLHandshakeException: java.security.cert.CertificateException: No subject alternative names present`        
    - 解决办法：     
        加上证书通过的代码。具体参考：     
        https://blog.csdn.net/it_dx/article/details/78866711        
        https://blog.csdn.net/audioo1/article/details/51746333      
2. 跨域问题的解决
    - 浏览器出现跨域：
    - 解决办法：     
        把下面这段加入到请求方法里。
        ```java
        /* 允许跨域的主机地址 */
        response.setHeader("Access-Control-Allow-Origin", "*");
        /* 允许跨域的请求方法GET, POST, HEAD 等 */
        response.setHeader("Access-Control-Allow-Methods", "*");
        /* 重新预检验跨域的缓存时间 (s) */
        response.setHeader("Access-Control-Max-Age", "3600");
        /* 允许跨域的请求头 */
        response.setHeader("Access-Control-Allow-Headers", "*");
        /* 是否携带cookie */
        response.setHeader("Access-Control-Allow-Credentials", "true");
        ```        
        
## 5. 终极解决法
proxy.jsp放在webapp下面，访问时不经过项目过滤，直接通过url就能访问，但是在`proxy.jsp`的`1082`行加入session验证,就能验证有没有登录了。    
```java
/**
 * 可以在这里获取session，不用写，比较直接
 * "key"换成登录时存的session就行了
 */
Object attribute = request.getSession().getAttribute("key");
if (null == attribute || "".equals(attribute.toString())) {
    String url = request.getContextPath() + "/login";
    response.sendRedirect(url);
}
```
