package gov.wyo.dragnet.helpers;

import static com.google.appengine.api.urlfetch.FetchOptions.Builder.validateCertificate;

import java.net.URL;
import java.util.HashMap;

import com.google.appengine.api.urlfetch.HTTPMethod;
import com.google.appengine.api.urlfetch.HTTPRequest;
import com.google.appengine.api.urlfetch.HTTPResponse;
import com.google.appengine.api.urlfetch.URLFetchService;
import com.google.appengine.api.urlfetch.URLFetchServiceFactory;

public class HttpHelper {

	public static String doGet(String targetURL) throws Exception {
		return doGet(targetURL, null);
	}
	
	public static String doGet(String targetURL, HashMap<String, String> headers) throws Exception {

		URLFetchService fetcher = URLFetchServiceFactory.getURLFetchService();
				
		URL url = new URL(targetURL);
		
		HTTPRequest request = new HTTPRequest(url, HTTPMethod.GET, validateCertificate());
		
		HTTPResponse response = fetcher.fetch(request);
		
		return new String(response.getContent());

	}
}
