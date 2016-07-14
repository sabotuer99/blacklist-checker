package gov.wyo.dragnet.blacklist;

import static org.junit.Assert.*;



import org.junit.Ignore;
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
	
	@Ignore
	@Test
	public void getHitCount_productionList() {
		//Arrange
		Query sut = new Query("127.0.0.7");
		
		//Act
		int count = sut.getHitCount(Blacklist.dnsBlacklists);
		System.out.println(count);
		
		//Assert
		assertTrue(true);
	}

	@Test
	public void getProjectHoneypotResult_testValue_allFieldsSetCorrect() {
		//Arrange
		Query sut = new Query("127.1.1.7");
		
		//Act
		HoneyPotResult result =  sut.getProjectHoneypotResult();
		
		//Assert
		assertFalse(result.isSearchEngine);
		assertTrue(result.isSuspicious);
		assertTrue(result.isHarvester);
		assertTrue(result.isCommentSpammer);
		assertEquals(1, result.daysLastSeen);
		assertEquals(1, result.threatScore);
	}
	
	@Test
	public void getProjectHoneypotResult_testNoResult_returnsNull() {
		//Arrange
		Query sut = new Query("127.0.0.1");
		
		//Act
		HoneyPotResult result =  sut.getProjectHoneypotResult();
		
		//Assert
		assertNull(result);
	}
	
	@Test
	public void getHitCount_experimentalList() {
		//Arrange
		Query sut = new Query("74.208.45.171");
		
		String[] bl = {
			"dnsbl.tornevall.org",
			"dnsbl.abuse.ch",
			"bl.blocklist.de",
			"bl.spamcop.net",
			"black.uribl.com",
			"multi.surbl.org"
		};
		
		//Act
		sut.getHitCount(bl);
		
		//Assert
		assertTrue(true);
	}
	
	//this test is no good because URLFetchService doesn't work locally
	@Ignore
	@Test
	public void getDShieldCount_sanityCheck() {
		//Arrange
		Query sut = new Query("70.91.145.10");
		
		//Act
		sut.getDShieldCount();
		
		//Assert
		assertTrue(true);
	}
	
	@Test
	public void parseDShieldResponse_GivenKnownResponse_ReturnsCorrectValue(){
		//Arrange
		String response = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ip><number>70.91.145.10</number><count>1477</count><attacks></attacks><maxdate></maxdate><mindate></mindate><updated></updated><comment></comment><maxrisk></maxrisk><asabusecontact>abuse@comcast.net</asabusecontact><as>7922</as><asname><![CDATA[COMCAST-7922 - Comcast Cable Communications, Inc.,]]></asname><ascountry>US</ascountry><assize>66192817</assize><network>70.88.0.0/14</network></ip>";
		Query sut = new Query();
		
		//Act
		int actual = sut.parseDShieldResult(response);
		
		//Assert
		assertEquals(1477, actual);
		
	}
	


}
