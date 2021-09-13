<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
    <head>

    </head>
    <body>
        <security:authorize access="isAuthenticated()">
            <h1>Привет, <security:authentication property="principal.username" /></h1>
        </security:authorize>

    </body>
</html>