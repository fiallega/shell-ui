package demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Created by ram on 8/24/2015.
 * Verifies the given token against Authorization User Service...
 *      - if the user service returns response type 200 - It is valid else invalid.
 */
@Service
@Scope("prototype")
public class VerifyToken {
    final static Logger logger = LoggerFactory.getLogger(VerifyToken.class);
    public VerifyToken(){}

    private String token = null;
    private URL url = null;
    public void setUrl(URL url) {
        this.url = url;
    }
    public void setToken(String token) {
        this.token = token;
    }

    public Boolean verify()
    {
        if(token == null || token.length() < 0){
            logger.debug("VerifyToken - verify : The Token is null");
            return false;
        }

        if(url == null )
        {
            logger.debug("VerifyToken - verify : The URl is null");
            return false;
        }

        HttpURLConnection connection = null;
        try
        {
            connection = (HttpURLConnection) url.openConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Authorization", "Bearer " + token);
            connection.connect();
            int connectionCode = connection.getResponseCode();
            if( connectionCode != HttpURLConnection.HTTP_OK){
                logger.debug("VerifyToken - verify : The Connection Code is " + connectionCode );
                return false;
            }
            logger.debug("VerifyToken - verify : The Connection Code is " + connectionCode );
            connection.disconnect();
            return true;
        }
        catch(MalformedURLException exception){
            logger.error(exception.getMessage());
            if(connection != null){
                connection.disconnect();
            }
            return false;
        }
        catch(IOException exception){
            logger.error(exception.getMessage());
            if(connection != null){
                connection.disconnect();
            }
            return false;
        }
        catch (Exception exception){
            logger.error(exception.getMessage());
            if(connection != null){
                connection.disconnect();
            }
            return false;
        }

    }
}
