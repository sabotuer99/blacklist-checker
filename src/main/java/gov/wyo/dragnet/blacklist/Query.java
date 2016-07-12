package gov.wyo.dragnet.blacklist;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import gov.wyo.dragnet.Constants;


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
	
	public int getHitCount(String[] bls){
		
		int count = 0;
		for(String bl : bls){
			long start =  System.currentTimeMillis();
			String host = revip + "." + bl;
			try {
				InetAddress result = InetAddress.getByName(host);
				System.out.println(result.toString());
				count++;
			} catch (UnknownHostException e) {
				//System.out.println(bl + " failed:" + e.getMessage());
				// Gulp
			}
			long duration =  System.currentTimeMillis() - start;
			System.out.println("Query of " + bl + " took " + duration);
		}
		
		return count;
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

	/* THIS IS WAAAAY MORE INVOLVED THEN IT NEES TO BE
	public int getThreat(String ip){
		
		String regex = "^(?:[0-9]{1,3}\\.[0-9]{1,3}\\.([0-9]{1,3})\\.[0-9]{1,3})$";
		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(ip);
		
		int threat = 0;
		if(matcher.find()){
			threat = Integer.parseInt(matcher.group(1));
		}
		
		return threat;
	}*/
	
	public void setIp(String ip){
		this.revip = reverseIp(ip);
		this.ip = ip;
	}
}
