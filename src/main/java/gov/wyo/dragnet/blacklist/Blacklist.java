package gov.wyo.dragnet.blacklist;

public class Blacklist {
	
	//wishlist of resources:
	//http://www.malwaredomainlist.com/hostslist/ip.txt
	//http://malc0de.com/bl/IP_Blacklist.txt
	//https://zeustracker.abuse.ch/blocklist.php?download=badips
	//https://www.autoshun.org/download/?api_key=<api_key>&format=csv
	//https://dshield.org/api/#ip
    //https://www.openbl.org/lists/base.txt
	//http://www.nothink.org/blacklist/blacklist_snmp_year.txt
	//https://developers.google.com/safe-browsing/v3/lookup-guide
	
	
	public static final String[] dnsBlacklists = {
			
		//blacklists I've found and tested, or at least verified active:
		"dnsbl.tornevall.org",
		"dnsbl.abuse.ch",
		"bl.blocklist.de",
		"bl.spamcop.net",
		"black.uribl.com",
		"multi.surbl.org",
		"spam.dnsbl.sorbs.net",
		"all.rbl.webiron.net",
		
		//list from https://github.com/IntellexApps/blcheck/blob/master/blcheck
		//"0spam-killlist.fusionzero.com",
		"0spam.fusionzero.com",
		"access.redhawk.org",
		"all.rbl.jp",
		"all.spam-rbl.fr",
		"all.spamrats.com",
		//"aspews.ext.sorbs.net",
		"b.barracudacentral.org",
		"backscatter.spameatingmonkey.net",
		//"badnets.spameatingmonkey.net", DEPRECATED
		//"bb.barracudacentral.org", SEEMS REDUNDANT
		"bl.drmx.org",
		"bl.konstant.no",
		"bl.nszones.com",
		"bl.spamcannibal.org",
		"bl.spameatingmonkey.net",
		"bl.spamstinks.com",
		"black.junkemailfilter.com",
		"blackholes.five-ten-sg.com",
		"blacklist.sci.kun.nl",
		"blacklist.woody.ch",
		"bogons.cymru.com",
		"bsb.empty.us",
		"bsb.spamlookup.net",
		"cart00ney.surriel.com",
		"cbl.abuseat.org",
		"cbl.anti-spam.org.cn",
		"cblless.anti-spam.org.cn",
		"cblplus.anti-spam.org.cn",
		"cdl.anti-spam.org.cn",
		"cidr.bl.mcafee.com",
		"combined.rbl.msrbl.net",
		"db.wpbl.info",
		"dev.null.dk",
		"dialups.visi.com",
		//"dnsbl-0.uceprotect.net",
		"dnsbl-1.uceprotect.net",
		"dnsbl-2.uceprotect.net",
		"dnsbl-3.uceprotect.net",
		"dnsbl.anticaptcha.net",
		//"dnsbl.aspnet.hu",
		"dnsbl.inps.de",
		"dnsbl.justspam.org",
		"dnsbl.kempt.net",
		"dnsbl.madavi.de",
		"dnsbl.rizon.net",
		"dnsbl.rv-soft.info",
		"dnsbl.rymsho.ru",
		"dnsbl.sorbs.net",
		"dnsbl.zapbl.net",
		"dnsrbl.swinog.ch",
		"dul.pacifier.net",
		//"dyn.nszones.com", INCLUDED IN BL
		//"dyna.spamrats.com", ALREADY IN ALL
		"fnrbl.fast.net",
		//"fresh.spameatingmonkey.net", DOMAIN ONLY
		//"hostkarma.junkemailfilter.com", INCLUDES WHITELIST
		//"images.rbl.msrbl.net", INCLUDED IN COMBINED
		"ips.backscatterer.org",
		"ix.dnsbl.manitu.net",
		"korea.services.net",
		//"l2.bbfh.ext.sorbs.net",
		//"l3.bbfh.ext.sorbs.net",
		//"l4.bbfh.ext.sorbs.net",
		"list.bbfh.org",
		"list.blogspambl.com",
		"mail-abuse.blacklist.jippg.org",
		"netbl.spameatingmonkey.net",
		//"netscan.rbl.blockedservers.com", ALREADY IN BASE BL
		"no-more-funn.moensted.dk",
		//"noptr.spamrats.com", ALREADY IN ALL
		"orvedb.aupads.org",
		//"pbl.spamhaus.org",ZEN includes already
		//"phishing.rbl.msrbl.net", INCLUDED IN COMBINED
		"pofon.foobar.hu",
		"psbl.surriel.com",
		"rbl.abuse.ro",
		"rbl.blockedservers.com",
		"rbl.dns-servicios.com",
		"rbl.efnet.org",
		"rbl.efnetrbl.org",
		"rbl.iprange.net",
		"rbl.schulte.org",
		"rbl.talkactive.net",
		"rbl2.triumf.ca",
		"rsbl.aupads.org",
		//"sbl-xbl.spamhaus.org",ZEN includes already
		//"sbl.nszones.com", INCLUDED IN BL
		//"sbl.spamhaus.org",ZEN includes already
		//"short.rbl.jp", INCLUDED IN ALL
		"spam.dnsbl.anonmails.de",
		"spam.pedantic.org",
		//"spam.rbl.blockedservers.com", ALREADY IN BASE BL
		//"spam.rbl.msrbl.net", INCLUDED IN COMBINED
		//"spam.spamrats.com", ALREADY IN ALL
		"spamrbl.imp.ch",
		"spamsources.fabel.dk",
		"st.technovision.dk",
		//"tor.dan.me.uk", UNNECESSARY
		"tor.dnsbl.sectoor.de",
		"tor.efnet.org",
		"torexit.dan.me.uk",
		"truncate.gbudb.net",
		"ubl.unsubscore.com",
		//"uribl.spameatingmonkey.net", INCLUDED IN URIRED
		"urired.spameatingmonkey.net",
		"virbl.dnsbl.bit.nl",
		//"virus.rbl.jp", INCLUDED IN ALL
		//"virus.rbl.msrbl.net", INCLUDED IN COMBINED
		//"vote.drbl.caravan.ru", SEEMS INACTIVE
		//"vote.drbl.gremlin.ru", SEEMS INACTIVE
		//"web.rbl.msrbl.net", INCLUDED IN COMBINED
		//"work.drbl.caravan.ru", SEEMS INACTIVE
		//"work.drbl.gremlin.ru", SEEMS INACTIVE
		"wormrbl.imp.ch",
		//"xbl.spamhaus.org", ZEN includes already
		"zen.spamhaus.org"		
	};
}
