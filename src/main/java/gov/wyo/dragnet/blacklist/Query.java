package gov.wyo.dragnet.blacklist;

import gov.wyo.dragnet.Constants;
import gov.wyo.dragnet.helpers.HttpHelper;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.appengine.api.ThreadManager;


public class Query {

	public String revip;
	public String ip;
	
    public Query(){}
    
	public Query(String ip){
		this.revip = reverseIp(ip);
		this.ip = ip;
	}
	
	public String reverseIp(String ip){
		
		String[] parts;
		String delineator;
		if(ip.contains(".")){
			 parts = ip.split("\\.");
			 delineator = ".";
		}
		else if(ip.contains(":")){
			 parts = ip.split(":");
			 delineator = ":";
		}
		else return "";
		
		List<String> partList = Arrays.asList(parts);
		Collections.reverse(partList);
		
		String reversed = "";
		for(String part : partList){
			reversed += part + delineator;
		}
		
		reversed = reversed.substring(0, reversed.length() - 1);
		
		return reversed;
	}
	
	/* Old synchronous version
	public int getHitCount(String[] bls){
		
		int count = 0;
		for(String bl : bls){			
			String host = revip + "." + bl;
			if(isHit(host))
				count++;
		}
		
		return count;
	}*/
	
	//same as get hit count, but uses isHitAsnyc
	public int getHitCount(String[] bls){
		
		int count = 0;
		List<Future<Boolean>> futes = new ArrayList<Future<Boolean>>();
		//get everybody started
		for(String bl : bls){			
			String host = revip + "." + bl;
			futes.add(isHitAsync(host));
		}
		
		//rack up the results
		for(Future<Boolean> result : futes){
			try {
				if(result.get())
					count++;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
			
		return count;
	}

	public boolean isHit(String host) {
		long start =  System.currentTimeMillis();
	    boolean isHit = false;
		
		try {
			InetAddress result = InetAddress.getByName(host);			
			System.out.println(result.toString());
			isHit = true;
		} catch (UnknownHostException e) {
			//System.out.println(bl + " failed:" + e.getMessage());
			// Gulp
		} catch (Exception e){
			System.out.println(host + " failed, but we're moving on...:" + e.getMessage());
		}
		long duration =  System.currentTimeMillis() - start;
		System.out.println("Query of " + host + " took " + duration);
		return isHit;
	}
	
	//private final ThreadFactory factory = ThreadManager.currentRequestThreadFactory();
	//private final ExecutorService pool = Executors.newCachedThreadPool(factory);
	public Future<Integer> getHitCountAsync(final String[] bls){

		ExecutorService pool = getPool();
		
		return pool.submit(new Callable<Integer>() {
			
			public Integer call() throws Exception {
				return getHitCount(bls);
			}
			
		});
	}
	
	
	public Future<Boolean> isHitAsync(final String host){		
		ExecutorService pool = getPool();		
		return pool.submit(new Callable<Boolean>() {			
			public Boolean call() throws Exception {
				return isHit(host);			
			}		
		});
	}
	
	public HoneyPotResult getProjectHoneypotResult(){
		if (revip == null)
			throw new RuntimeException("Ip must be set first!");
		
		HoneyPotResult hpr = null;
		String host = Constants.PROJECTHONEYPOT_KEY + "." + revip + ".dnsbl.httpbl.org";
		
		try {
			InetAddress result = InetAddress.getByName(host);
			System.out.println(result.toString());

			String[] parts = result.toString().split("/")[1].split("\\.");
			hpr = new HoneyPotResult();
			hpr.daysLastSeen = Integer.parseInt(parts[1]);
			hpr.threatScore = Integer.parseInt(parts[2]);
			int ttype = Integer.parseInt(parts[3]);
			hpr.isSearchEngine = ttype == 0;
			hpr.isSuspicious = ttype % 2 == 1;
			ttype >>= 1;
			hpr.isHarvester = ttype % 2 == 1;
			ttype >>= 1;
			hpr.isCommentSpammer = ttype % 2 == 1;
		} catch (UnknownHostException e) {
			//System.out.println(bl + " failed:" + e.getMessage());
			// Gulp
		}
		
		return hpr;
	}

	public int getDShieldCount(){
		try {
			String url = "https://dshield.org/api/ip/" + ip;
			String response = HttpHelper.doGet(url);
			
			return parseDShieldResult(response);

		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		
		return 0;
	}
	
	public int parseDShieldResult(String result){
		
		String regex = "<count>(.*)</count>";
		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(result);
		if(matcher.find()){
			return Integer.parseInt(matcher.group(1));
		}		
		return 0;
	}
	
	public void setIp(String ip){
		this.revip = reverseIp(ip);
		this.ip = ip;
	}
	
	
	private ExecutorService pool = null;
	private ExecutorService getPool(){
		
		if(this.pool == null){
		
			ThreadFactory factory = null;
			try{ 
				factory = ThreadManager.currentRequestThreadFactory();
			} catch (Exception ex) {
				
			}			
			
			if(factory != null) {
				pool = Executors.newFixedThreadPool(49, factory);
			} else {
				pool = Executors.newFixedThreadPool(49);
			}
		}
		
		return pool;
		
	}
}
