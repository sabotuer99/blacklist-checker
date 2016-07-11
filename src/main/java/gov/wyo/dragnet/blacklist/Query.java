package gov.wyo.dragnet.blacklist;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;


public class Query {

	public String revip;
	
    public Query(){}
    
	public Query(String ip){
		this.revip = reverseIp(ip);
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
	
}
