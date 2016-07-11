package gov.wyo.dragnet.blacklist;

import static org.junit.Assert.*;

import org.junit.Test;

public class QueryTests {

	@Test
	public void reverseIp_givenValidIPv4_returnsCorrectReversal() {
		//Arrange
		Query sut = new Query();
		
		//Act
		String result = sut.reverseIp("127.1.2.3");
		
		//Assert
		assertEquals("3.2.1.127", result);
	}
	
	@Test
	public void reverseIp_givenValidIPv6_returnsCorrectReversal() {
		//Arrange
		Query sut = new Query();
		
		//Act
		String result = sut.reverseIp("2001:0DB8:AC10:FE01:0000:0000:0000:0000");
		
		//Assert
		assertEquals("0000:0000:0000:0000:FE01:AC10:0DB8:2001", result);
	}
	
	@Test
	public void getHitCount_productionList() {
		//Arrange
		Query sut = new Query("159.238.66.51");
		
		//Act
		sut.getHitCount(Blacklist.dnsBlacklists);
		
		//Assert
		assertTrue(true);
	}

}