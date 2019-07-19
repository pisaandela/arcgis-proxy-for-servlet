# v1.1.2版的arcgis代理servlet版
## 1. 老版本存在的问题
- 官方库中没有servlet版本，只有jsp版，并不能用在分离的项目中。   
https://github.com/Esri/resource-proxy

- 别人的servlet版本比较老，且基于netbean，不能直接导入到idea或者eclipse中。     
https://github.com/Outtascope/servlet-proxy

## 2. 改造后的几个版本
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