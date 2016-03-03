package demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Service;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URL;

/**
 * Created by ram on 8/24/2015.
 * As per of single sign out process ...
 *
 *      - It validate the Token when the request is coming from root (/).
 *      - If the token is valid, It will continue the filter processing.
 *      - If the token is NOT valid, then it will clear the cookies and redirect to /login page.
 */
@Service
public class WasdSelfServiceUiFilter implements Filter {
    final static Logger logger = LoggerFactory.getLogger(WasdSelfServiceUiFilter.class);
    @Autowired
    AppConstants appConstants;

    @Autowired
    VerifyToken verifyToken;

    @Override
    public void destroy() {
    //do nothing
    }

    /**
     * Verify the token. If the token is not valid, clear cookies and redirect to login page
     * @param servletRequest
     * @param servletResponse
     * @param filterChain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException
    {
        logger.debug("userUrl :" + appConstants.getUserUrl());

        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;

        if((httpServletRequest.getRequestURI().equalsIgnoreCase(httpServletRequest.getContextPath()+"/") ||
                httpServletRequest.getRequestURI().toLowerCase().contains("/wasd/selfservice/api/")))
        {
            logger.debug("RequestURI : " + httpServletRequest.getRequestURI() );
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if(authentication == null){
                logger.debug("Authentication is null");
                ClearCookiesAndRedirectToLoginPage(httpServletRequest, httpServletResponse);
            }
            if(authentication instanceof AnonymousAuthenticationToken){
                logger.debug("Authentication is AnonymousAuthenticationToken");
                ClearCookiesAndRedirectToLoginPage(httpServletRequest, httpServletResponse);
            }
            if(authentication instanceof OAuth2Authentication)
            {
                Object details = authentication.getDetails();
                if(details instanceof OAuth2AuthenticationDetails)
                {
                    OAuth2AuthenticationDetails oauth =(OAuth2AuthenticationDetails) details;
                    String token = oauth.getTokenValue();
                    logger.debug("oauth2Token value : " + token);

                    //Verify the token
                    verifyToken.setToken(token);
                    verifyToken.setUrl(new URL(appConstants.getUserUrl()));
                    if(verifyToken.verify())
                    {
                        logger.debug("The Token is valid : " + token);
                        filterChain.doFilter(httpServletRequest, httpServletResponse);
                    }
                    else {
                        //The token is invalid... So clear cookies and redirect to /login page
                        logger.debug("Token is NOT valid : " + token);
                        ClearCookiesAndRedirectToLoginPage(httpServletRequest, httpServletResponse);
                    }
                }
            }
        }
        if(!httpServletResponse.isCommitted()) {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
        }

    }

    /**
     * Clear Cookies and Redirect to Login Page
     * @param httpServletRequest
     * @param httpServletResponse
     * @throws IOException
     */
    private void ClearCookiesAndRedirectToLoginPage(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        Cookie[] cookies = httpServletRequest.getCookies();

        if(cookies != null){
            logger.debug("Clear Cookies");
        for (int j = 0; j < cookies.length; j++) {
            cookies[j].setValue("");
            cookies[j].setPath(cookies[j].getPath());
            cookies[j].setMaxAge(0);
            httpServletResponse.addCookie(cookies[j]);
        }}

        HttpSession session = httpServletRequest.getSession(false);
        if(session != null){
            logger.debug("Invalidate Session");
            session.invalidate();
        }

        //Redirect to login page
        logger.debug("Redirected to login page!!!");
        httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        if(httpServletRequest.getRequestURI().toLowerCase().contains("/wasd/selfservice/api/")) {
            httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authorization Failed");
        }
        else{
            httpServletResponse.sendRedirect("login");
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    //Do nothing
    }
}
