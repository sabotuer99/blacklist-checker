package gov.wyo.dragnet;

import java.util.concurrent.Future;

import gov.wyo.dragnet.blacklist.Blacklist;
import gov.wyo.dragnet.blacklist.HoneyPotResult;
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
    	
    	Future<HoneyPotResult> hpr = q.getProjectHoneypotResultAsync();
    	Future<Integer> dsr = q.getDShieldCountAsync();
    	Future<Integer> blc = q.getHitCountAsync(Blacklist.dnsBlacklists);
    	
    	BLResult result = new BLResult();
    	/*
    	result.honeyPotResult = q.getProjectHoneypotResult();
    	result.dSheildCount = q.getDShieldCount();
    	result.blackListHitCount = q.getHitCount(Blacklist.dnsBlacklists);
    	*/
    	try{
	    	result.honeyPotResult = hpr.get();
	    	result.dSheildCount = dsr.get();
	    	result.blackListHitCount = blc.get();
    	} catch (Exception ex){
    		result = null;
    	}
    	
    	return result;
    }
    
    @ApiMethod(name = "dshield", httpMethod = HttpMethod.GET)
    public BLResult dshield(@Named("ip") String ip){
    	
    	Query q = new Query(ip);
    	BLResult result = new BLResult();
    	result.dSheildCount = q.getDShieldCount();
    	return result;
    }

}
