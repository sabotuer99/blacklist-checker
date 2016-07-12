package gov.wyo.dragnet;

import gov.wyo.dragnet.blacklist.Blacklist;
import gov.wyo.dragnet.blacklist.Query;

import com.google.api.server.spi.config.Api;
import com.google.api.server.spi.config.ApiMethod;
import com.google.api.server.spi.config.ApiMethod.HttpMethod;
import com.google.api.server.spi.config.Named;

/**
 * Defines endpoint functions APIs.
 */
@Api(name = "dragnetendpoints", version = "v1",
scopes = {Constants.EMAIL_SCOPE },
        clientIds = {Constants.WEB_CLIENT_ID, Constants.API_EXPLORER_CLIENT_ID },
        description = "API for dragnet endpoints.")

public class DragnetEndpoints {
    
    @ApiMethod(name = "check", httpMethod = HttpMethod.GET)
    public BLResult check(@Named("ip") String ip){
    	
    	Query q = new Query(ip);
    	
    	BLResult result = new BLResult();
    	result.blackListHitCount = q.getHitCount(Blacklist.dnsBlacklists);
    	result.honeyPotResult = q.getProjectHoneypotResult();  	
    	
    	return result;
    }

}
