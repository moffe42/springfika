<?php
error_reporting(E_ALL ^E_NOTICE);

/**
	SLO currently unsupported
			
	NTS:
		error handling ...
		correct handling of WantAssertionsSigned signed assertions - now only checks signature for request and response
			need xml when checking signature after encryption ...
		configurable NameIDFormat
		always encrypted when json 
		
		metadata cleanup - representing metadata in standard xml2hash format ???
			with a possibility for xtra params eg. filter ...

		myWayf ...
			heimat using idp initiated login -> dummy sp which just returns -> saves one roundtrip, saves use of scoping

		hosted should only be stated one place - at the "guest"
		auth should always be remote, but might be hosted ...
		"remote" json idp ...
		+ filters
		+ handling of AssertionConsumerServiceIndex, , AttributeConsumingServiceIndex
		+ check of destination, issuer, audience, sessiontime ..
		- for cached responses as well ...
		+ EncryptedAssertion
		+ EncryptedAttribute
		+ URI binding - assertionURL
		+ soap - attributequery, 
		+ relaystate should be sent back
		+ proxyCount 
		+ encryption ...
		+ real xml signing for post binding
		+ post binding
		+ multi session wayf ...
		+ attribute filters - check for existence of function ...
		+ consent ...
		+ virtual idps 
		+ attribute collector ...
		+ one file only
		+ virtual idp (ie. attribute collector)
		+ embedded vidp
		+ debugging via external logfile ...

*/

$baseurl = selfUrl();

$metabase = array(
	'hosted' => array(
		$baseurl."wayf" => array(
			'infilter' => 'infilter',
			'outfilter' => 'outfilter',
		),
		$baseurl."idp1" => array(
			'idp' => $baseurl."null",
			'infilter' => 'infilter',
			'outfilter' => 'outfilter',
			#'keepsession' => true,
		),
		$baseurl."idp2" => array(
			#'IDPList' =>  array($baseurl."idp1"),
			#'idp' => $baseurl.'wayf',
			#'key' => 'server_pem',
			'idp' => $baseurl."null",
			'infilter' => 'infilter',
			'outfilter' => 'outfilter',
			#'keepsession' => true,
		),
		$baseurl."vidp1" => array(
			'virtual' => array($baseurl."idp1", $baseurl."idp2"),
			'key' => 'server_pem',
			'infilter' => 'infilter',
			'outfilter' => 'outfilter',
		),
	),
	'remote' => array(
		$baseurl.'main' => array(
			'sharedkey' => 'abracadabra',
			'spfilter' => 'spfilter',
			'AssertionConsumerService' => array(
					'Location' => $baseurl."main/demoapp",
					'Binding' => 'urn:oasis:names:tc:SAML:1.0:profiles:browser-post',	
			),
		),
		$baseurl."wayf" => array(
			'WantAssertionsSigned'	=> true,
			'AuthnRequestsSigned'	=> true,
			'AssertionConsumerService' => array(
					'Location' => $baseurl."wayf/assertionConsumerService",
					'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',	
			),
			'SingleSignOnService' => array(
				'Binding' 	=> 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
				'Location' 	=> $baseurl.'wayf/singleSignOnService',
			),
			'ArtifactResolutionService' => array(
				'Binding'	=> 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
				'Location' => $baseurl.'wayf/ArtifactResolutionService',
			),
			'filter' => 'idpfilter',
			'filter' => 'spfilter',
			'key' => 'server_pem',
		),
		$baseurl.'null' => array(
			'SingleSignOnService' => array(
				'Binding' 	=> 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
				'Location' 	=> $baseurl.'null/nullSingleSignOnService',
			),
		
		),
		$baseurl."idp1" => array(
			'SingleSignOnService' => array(
				'Binding' 	=> 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
				'Location' 	=> $baseurl.'idp1/singleSignOnService',
			),
			'AssertionConsumerService' => array(
					'Location' => $baseurl."idp1/assertionConsumerService",
					'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',	
			),
			'ArtifactResolutionService' => array(
				'Binding'	=> 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
				'Location' => $baseurl.'idp1/ArtifactResolutionService',
			),
			'filter' => 'idpfilter',
			'WantAuthnRequestsSigned' =>  true,
			#'publickey' => 'server_crt',
		),
		$baseurl."idp2" => array(
			'AssertionConsumerService' => array(
					'Location' => $baseurl."idp2/assertionConsumerService",
					'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',	
			),
			'SingleSignOnService' => array(
				'Binding' => 'urn:mace:shibboleth:1.0:profiles:AuthnRequest',	
				'Location' 	=> $baseurl.'idp2/shibSingleSignOnService',
			),
			'ArtifactResolutionService' => array(
				'Binding'	=> 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
				'Location' => $baseurl.'idp2/ArtifactResolutionService',
			),
			'filter' => 'idpfilter',
			'publickey' => 'wayfwildcard',
			'filter' => 'spfilter',
		),
		$baseurl."vidp1" => array(
			'AssertionConsumerService' => array(
					'Location' => $baseurl."vidp1/handleVirtualIDP",
					'Binding' => 'INTERNAL',	
			),
			'SingleSignOnService' => array(
				'Binding' 	=> 'INTERNAL',
				'Location' 	=> $baseurl.'vidp1/handleVirtualIDP',
			),
			'ArtifactResolutionService' => array(
				'Binding'	=> 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
				'Location' => $baseurl.'vidp1/ArtifactResolutionService',
			),
			'filter' => 'idpfilter',
			'publickey' => 'server_crt',
			'filter' => 'spfilter',
		),
		'http://jach-idp.test.wayf.dk/saml2/idp/metadata.php' => Array (
			'SingleSignOnService' => array(
				'Binding' 	=> 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
				'Location' 	=> 'http://jach-idp.test.wayf.dk/saml2/idp/SSOService.php',
			),
			'filter' => 'idpfilter',
			'publickey' => 'wayfwildcard',
		),
		'http://jach-idp.test.wayf.dk/saml2/idp/metadata.php' => Array (
			'SingleSignOnService' => array(
				'Binding' 	=> 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
				'Location' 	=> 'http://jach-idp.test.wayf.dk/saml2/idp/SSOService.php',
			),
			'filter' => 'idpfilter',
			'publickey' => 'wayfwildcard',
		),
		'https://orphanage.wayf.dk' => Array (
			'SingleSignOnService' => array(
				'Binding' 	=> 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
				'Location' 	=> 'https://orphanage.wayf.dk/saml2/idp/SSOService.php',
			),
			'filter' => 'idpfilter',
			'publickey' => 'wayfwildcard',
		),
	),
);

foreach($metabase as $type => &$value) {
	foreach($value as $entityid => &$entity) {
		$entity['EntityID'] = $entityid;
		if ($ars = $entity['ArtifactResolutionService']) $artifactResolutionServices[sha1($entityid)] = $ars;
	}
}

define('SIGALG', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');
define('DEBUG', 0);
define('TRACE', 0);
define('WAYF', $baseurl . 'wayf');
define('DEBUGLOG', '/tmp/zzz.log');

list($entitycode, $cmd) = preg_split('/[\/?]/', $_SERVER['PATH_INFO'], 0, PREG_SPLIT_NO_EMPTY);
if (!$entitycode) $entitycode = 'main';
if (!$cmd) $cmd = 'demoapp';

list($entitycode, $idp) = preg_split('/_/', $entitycode, 0, PREG_SPLIT_NO_EMPTY);

$entityid = $baseurl.$entitycode;
$meta = $metabase['hosted'][$entityid];
if ($idp) $meta['idp'] = $baseurl.$idp;
$meta['EntityID'] = $entityid;
$meta['entitycode'] = $entitycode;

session_set_cookie_params(0, selfPath(), '', true);
session_name($entitycode);
session_start();

prepareparams();
if (method_exists( 'userfuncs', $cmd)) userfuncs::$cmd();
else $cmd();

function demoapp() { Demo::demoapp(); };

function prepareparams() {
	if ($_REQUEST['SAMLArt']) handleArtifact();
	else {
		if ($_GET['Signature']) foreach(explode("&", $_SERVER['QUERY_STRING']) as $p) if (preg_match("/^(.+)=(.*)$/", $p, $d))  {$rawreq[$d[1]] = $d[2];}
		
		foreach(array('SAMLRequest', 'SAMLResponse') as $req) {
			unset($message);
			$hreq = 'h'.$req;
			if ($_POST[$req]) 		$message = base64_decode($_POST[$req]);
			if ($_GET[$req]) 		$message = gzinflate(base64_decode($_GET[$req]));
			if ($message) 			$_REQUEST[$hreq] = xh::xml2hash($message);
			if ($_GET['j'.$req]) 	$_REQUEST[$hreq] = json_decode(gzinflate(base64_decode($_GET['j'.$req])), 1);
			if (!$_REQUEST[$hreq]) continue;
			if ($rs = $_REQUEST['RelayState']) $_REQUEST[$hreq]['__']['RelayState'] = $rs;
			$remotemeta = $GLOBALS['metabase']['remote'][$_REQUEST[$hreq]['saml:Issuer']['__v']];
			$verify = ($req == 'SAMLRequest' && ($remotemeta['AuthnRequestsSigned'] || $GLOBALS['meta']['WantAuthnRequestsSigned']))
						|| ($req == 'SAMLResponse' && $GLOBALS['meta']['WantAssertionsSigned']);
			if ($verify ) {
				if ($sharedkey = $remotemeta['sharedkey']) {
					if ($_GET['Signature']) $message = "j$req=" . $rawreq['j'.$req] . (($relaystate = $rawreq['RelayState']) ? '&RelayState=' . $relaystate : '');
					else $message = $_POST['j'.$req];
					if (base64_encode(sha1($sharedkey . sha1($message))) != $_REQUEST['Signature']) die('Integrity check failed (Sharedkey)');
				} elseif ($signature = $_GET['Signature']) {
					$message = "$req=" . $rawreq[$req] . (($relaystate = $rawreq['RelayState']) ? '&RelayState=' . $relaystate : '') . '&SigAlg=' . $rawreq['SigAlg'];
					if (openssl_verify($message, base64_decode($signature), certs::$server_crt) != 1) die('Integrity check failed (PKI)');
				} else {
					$verified = verify(certs::$server_crt, $message, $_REQUEST[$hreq]) || verify(certs::$server_crt, $message, $_REQUEST[$hreq]['saml:Assertion']);					
					if (!verified) die("Could not validate " . print_r($_REQUEST[$hreq],1));
				}
			}
		}
	}
	if ($ea = $_REQUEST['hSAMLResponse']['saml:EncryptedAssertion']) $$_REQUEST['hSAMLResponse']['saml:Assertion'] = dodecrypt(certs::$$GLOBALS['meta']['privatekey'], $ea);
	prepareforSLO($_REQUEST['hSAMLResponse'], 'received');
	checkDestinationAudienceAndTiming();
}

function singleSignOnService() {
	$req = $_REQUEST['hSAMLRequest'];
	$scopedIDPs = array();
	if ($req['_ForceAuthn']) 					unset($_SESSION['CachedResponses'], $_SESSION['CachedIDP']);
	if ($IDPList = $req['samlp:Scoping']['samlp:IDPList']['samlp:IDPEntry']) 
												foreach($IDPList as $IDPEntry) $scopedIDPs[] = $IDPEntry['_ProviderID'];
	if ($_SESSION['CachedResponses'] && ($cachedidps = array_intersect(array_keys($_SESSION['CachedResponses']), $scopedIDPs))) 
												sendResponse($req, createResponse($req, null, null, $_SESSION['CachedResponses'][$cachedidps[0]]));
	if (isset($req['samlp:Scoping']['_ProxyCount']) && $req['samlp:Scoping']['_ProxyCount'] == 0) sendResponse($req, createResponse($req, 'ProxyCountExceeded'));
	if ($scope = $GLOBALS['meta']['IDPList']) 	sendAuthnRequest($GLOBALS['meta']['idp'], $scope);
	if ($idp = $GLOBALS['meta']['idp']) 		sendAuthnRequest($idp);
	if ($idps = $GLOBALS['meta']['virtual']) 	handleVirtualIDP($idps);

	foreach($GLOBALS['metabase']['remote'] as $idp => $metadata) if ($metadata['SingleSignOnService']) $candidateIDPs[] = $idp;
	$candidateIDPs = array_diff($candidateIDPs, array($GLOBALS['meta']['EntityID']));
	$candidateIDPs = sizeof($scopedIDPs) > 0 ? array_intersect($scopedIDPs, $candidateIDPs) : $candidateIDPs;
	if (sizeof($candidateIDPs) == 1) 			sendAuthnRequest($candidateIDPs[0]);
	if (sizeof($candidateIDPs) == 0) 			sendResponse($req, createResponse($req, 'NoSupportedIDP'));
	discover($candidateIDPs); # discover should take are of IsPassive ...
}

function assertionConsumerService() {
	$response = $_REQUEST['hSAMLResponse'];
	infilter($response);
	if ($GLOBALS['meta']['keepsession']) { $_SESSION['CachedResponses'][$response['saml:Issuer']['__v']] = $response; }
	$id = $_POST['target'] ? $_POST['target'] : $response['_InResponseTo'];
	$origRequest = $_SESSION[$_SESSION[$id]['_InResponseTo']]['hSAMLRequest'];
	if (!$origRequest) die('No origRequest: ' . $_SESSION[$id]['_InResponseTo']);
	unset($_SESSION[$id]['_InResponseTo']);
	sendResponse($origRequest, createResponse($origRequest, null, null, $response));
}

function artifactResolutionService() {
	$postdata = xh::xml2hash(file_get_contents("php://input"));
	$artifact = $postdata['SOAP-ENV:Body']['samlp:ArtifactResolve']['saml:Artifact']['__v'];
	newsession(sha1($artifact),'artifact');
	$message = $_SESSION['message'];
	session_destroy();
	$element = $message['__t'];
	$artifactresponse = array(
		'samlp:ArtifactResponse' => array(
			'xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
			'xmlns:saml' => 'urn:oasis:names:tc:SAML:2.0:assertion',
			'ID' => ID(),
			'Version' => '2.0',
			'IssueInstant' => timeStamp(),
			'InResponseTo' => $postdata['SOAP-ENV:Body']['samlp:ArtifactResolve']['_ID'],
			'saml:Issuer' => array('__v' => $GLOBALS['meta']['EntityID']),
			$element => $message,
		),
	);
	soapResponse($artifactresponse);
}

function attributeService() {
	$postdata = xh::xml2hash(file_get_contents("php://input"));
	$subject = $postdata['SOAP-ENV:Body']['samlp:AttributeQuery']['saml:Subject']['saml:NameID']['__v'];
	soapResponse(array('saml:Response' => createResponse($postdata['SOAP-ENV:Body']['samlp:AttributeQuery'])));
}

function assertionService() {
	newsession($_GET['ID'], 'assertion');
	header('Content-Type: application/samlassertion+xml');
	$as = $_SESSION['assertion'];
	if ($as) print xh::h2x($as, 'saml:Assertion');
}

function sendAuthnRequest($idp, $scope = null) {
	$id = $_REQUEST['hSAMLRequest']['_ID'];
	$_SESSION[$id]['hSAMLRequest'] = $_REQUEST['hSAMLRequest'];
	$newRequest = createRequest($idp, $scope);
	$_SESSION[$newRequest['_ID']]['_InResponseTo'] = $id;
	send($newRequest, $GLOBALS['metabase']['remote'][$idp]);
}

function sendResponse($request, $response) {
	if ($response['samlp:Status']['samlp:StatusCode']['_Value'] == 'urn:oasis:names:tc:SAML:2.0:status:Success') {
		outfilter($response);
		prepareforSLO($response, 'sent');
		send($response, $GLOBALS['metabase']['remote'][$request['saml:Issuer']['__v']]);
		$id = $response['_ID'];
		$_SESSION['consent'][$id]['request'] = $request;
		$_SESSION['consent'][$id]['response'] = $response;
		$attributes = xh::a2h($response['saml:Assertion']['saml:AttributeStatement']['saml:Attribute']);
		print render('consent', array('action' => selfUrl() . 'continue2sp', 'ID' => $id, 'attributes' => $attributes, 'c' => $GLOBALS['c']));
		exit;
	}
	unset($response['saml:Assertion']);
	send($response, $GLOBALS['metabase']['remote'][$request['saml:Issuer']['__v']]);
}

function continue2sp() {
	$request = $_SESSION['consent'][$_POST['ID']]['request'];
	$response = $_SESSION['consent'][$_POST['ID']]['response'];
	unset($_SESSION['consent'][$_POST['ID']]);
	send($response, $GLOBALS['metabase']['remote'][$request['saml:Issuer']['__v']]);
}

function discover($candidateIDPs) {
	$req = $_REQUEST['hSAMLRequest'];
	if ($req['_IsPassive'] == 'true') sendResponse($req, createResponse($req, 'NoPassive'));
	$id = $req['_ID'];
	$_SESSION[$id]['hSAMLRequest'] = $req;
	$action = selfUrl() . 'continue2idp';
	print render('discover', array('action' => $action, 'ID' => $id, 'idpList' => $candidateIDPs));
}

function continue2idp() {
	$_REQUEST['hSAMLRequest'] = $_SESSION[$_POST['ID']]['hSAMLRequest'];
	sendAuthnRequest($_REQUEST['idp']);
}

function handleVirtualIDP($idps = null) {
	if ($req = $_REQUEST['hSAMLRequest']) {
		unset($_SESSION['virtual']);
		$_SESSION['virtual']['idps'] = $GLOBALS['meta']['virtual'];
		$_SESSION['virtual']['hSAMLRequest'] = $req;
		$_SESSION['virtual']['idp'] = $GLOBALS['meta']['EntityID'];
	} elseif ($res = $_REQUEST['hSAMLResponse']) {
		infilter($res);
		$aa = end($res['saml:Assertion']['saml:AuthnStatement']['saml:AuthnContext']['saml:AuthenticatingAuthority']);
		#if (!$aa) $aa = $res['saml:Issuer'];
		$_SESSION['virtual']['hSAMLResponses'][$aa['__v']] = $res;
	} else die("What! No Kissing?");
	foreach((array)$_SESSION['virtual']['idps'] as $idp) {
		if (!$_SESSION['virtual']['hSAMLResponses'][$idp]) {
			$newRequest = createRequest(WAYF, $idp);
			#$newRequest = createRequest($idp);
			$newRequest['_AssertionConsumerServiceURL'] = $_SESSION['virtual']['idp'] . "/" . __FUNCTION__;
			send($newRequest, $GLOBALS['metabase']['remote'][WAYF]);
		}
	}
	foreach((array)$_SESSION['virtual']['hSAMLResponses'] as $idp => $response) {
		$attrs = xh::a2h($response['saml:Assertion']['saml:AttributeStatement']['saml:Attribute']);
		foreach($attrs as $name => $values) {
			foreach($values as $value) {
				$combinedattrs[$name][] = $value;
			}
		}
	}
	$origRequest = $_SESSION['virtual']['hSAMLRequest'];
	$finalresponse = createResponse($origRequest, null, $combinedattrs);
	unset($_SESSION['virtual']);
	send($finalresponse, $GLOBALS['metabase']['remote'][$origRequest['saml:Issuer']['__v']]);
}

function handleArtifact() {
	$artifacts = unpack('ntypecode/nendpointindex/H40sourceid/H40messagehandle', base64_decode($_REQUEST['SAMLArt']));
	$artifactresolve = array(
		'samlp:ArtifactResolve' => array(
			'_xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
			'_xmlns:saml' => 'urn:oasis:names:tc:SAML:2.0:assertion',
			'_ID' => ID(),
			'_Version' => '2.0',
			'_IssueInstant' => timeStamp(),
			'saml:Artifact' => array('__v' => $_REQUEST['SAMLArt']),
			'saml:Issuer' => array('__v' => $GLOBALS['meta']['EntityID']),
		),
	);

	$artifactresponse = soapRequest($GLOBALS['artifactResolutionServices'][$artifacts['sourceid']], $artifactresolve);
	if ($_REQUEST['hSAMLResponse'] = $artifactresponse['samlp:ArtifactResponse']['samlp:Response'])
		$_REQUEST['hSAMLResponse']['__t'] = 'samlp:Response';
	if ($_REQUEST['hSAMLRequest'] = $artifactresponse['samlp:ArtifactResponse']['samlp:AuthnRequest'])
		$_REQUEST['hSAMLRequest']['__t'] = 'samlp:AuthnRequest';
}

function soapRequest($soapService, $element) {
	$soapEnvelope = array(
		'__t' => 'SOAP-ENV:Envelope', 
		'xmlns:SOAP-ENV' => "http://schemas.xmlsoap.org/soap/envelope/",
		'SOAP-ENV:Body' => $element,
	);

	$ch = curl_init(); 
	$curlopts = array(
		CURLOPT_URL 			=> $soapService, 
		CURLOPT_HTTPHEADER 		=> array('SOAPAction: ""'),    
		CURLOPT_RETURNTRANSFER 	=> 1,
		CURLOPT_SSL__vERIFYPEER 	=> FALSE,
		CURLOPT_POSTFIELDS 		=> xh::h2x($soapEnvelope),
		CURLOPT_HEADER 			=> 0,
	);
	curl_setopt_array($ch, $curlopts);
	$soapResponse = xh::xml2hash(curl_exec($ch));
	return $soapResponse['SOAP-ENV:Body'];
}

function soapResponse($element) {
	$soapresponse = array(
		'__t' => 'SOAP-ENV:Envelope', 
		'xmlns:SOAP-ENV' => "http://schemas.xmlsoap.org/soap/envelope/",
		'SOAP-ENV:Body' => $element,
	);
	print xh::h2x($soapresponse);
}

function send($message, $metadata) {
	$bindings = array(
		'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'		=> 'sendHTTPRedirect',	
		'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' 			=> 'sendHTTPPost',
		'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact' 		=> 'sendHTTPArtifact',
		'urn:oasis:names:tc:SAML:2.0:bindings:URI'					=> 'sendURI',
		'urn:oasis:names:tc:SAML:2.0:bindings:SOAP'					=> 'sendSOAP',
		'INTERNAL'													=> 'sendInternal',
		'JSON-Redirect'												=> 'sendHTTPRedirect',
		'JSON-POST'													=> 'sendHTTPPost',
		null														=> 'sendHTTPRedirect',

		'urn:oasis:names:tc:SAML:1.0:profiles:browser-post'			=> 'sendbrowserpost',
		'urn:oasis:names:tc:SAML:1.0:profiles:browser-artifact-01'	=> 'sendbrowserartifact01',
		'urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding'			=> 'xxxx',
		'urn:mace:shibboleth:1.0:profiles:AuthnRequest'				=> 'sendShibAuthnRequest',
	);
	$function = $bindings[$message['__']['ProtocolBinding']];
	$function($message, $metadata);
}

function sendHTTPRedirect($message, $metadata) {
	$name = $message['__']['paramname'];
	$sign = $name == 'SAMLRequest' && ($metadata['WantAuthnRequestsSigned'] || $GLOBALS['meta']['AuthnRequestsSigned']);
	if (!$sign) unset($message['ds:Signature']);
	$location = $message['_Destination'] . $message['_Recipient']; # shib remember ...
	$newmessage = $metadata['json'] ? json_encode($message) : xh::h2x($message);
	$newmessage = urlencode(base64_encode(gzdeflate($newmessage)));
	$newmessage = ($message['__']['ProtocolBinding'] == 'JSON-Redirect' ? "j"  : "") . "$name=" . $newmessage;
	$newmessage .= $message['__']['RelayState'] ? '&RelayState=' . urlencode($message['__']['RelayState']) : "";
	$newmessage .= $message['__']['target'] ? '&target=' . urlencode($message['__']['target']) : "";
	if ($sharedkey = $metadata['sharedkey']) {
		$newmessage .= "&Signature=" . urlencode(base64_encode(sha1($sharedkey . sha1($newmessage))));
	} elseif ($sign) {
		$newmessage .= '&SigAlg=' . urlencode(SIGALG);
		$key = openssl_pkey_get_private(certs::$server_key);
		openssl_sign($newmessage, $signature, $key);
		openssl_free_key($key);
		$newmessage .= '&Signature=' . urlencode(base64_encode($signature));
	}
	$location .=  "?" . $newmessage;	
	redirect($location, $message);
}

function sendHTTPPost($message, $metadata) {
	$name = $message['__']['paramname'];
	$action = $message['_Destination'] . $message['_Recipient'];
	if (TRACE) $x = debugrequest($action, $message);
	$xtra = $message['__']['RelayState'] ? '<input type="hidden" name="RelayState" value="' . htmlspecialchars($message['__']['RelayState']) . '">' : '';
	$xtra .= $message['__']['target'] ? '<input type="hidden" name="target" value="' . htmlspecialchars($message['__']['target']) . '">' : '';
	if ($message['__']['ProtocolBinding'] == 'JSON-POST') {
		if ($rs = $message['__']['RelayState']) $rs = "&RelayState=$rs";
		$name = 'j' . $name;
		$message = json_encode($message);
		$xtra .= '<input type="hidden" name="Signature" value="' . htmlspecialchars(base64_encode(sha1($metadata['sharedkey'] . sha1("$name=$message$rs")))) . '">';
	} elseif ($name == 'SAMLRequest' && ($metadata['WantAuthnRequestsSigned'] || $GLOBALS['meta']['AuthnRequestsSigned'])) {
		$message['ds:Signature'] = sign(certs::$server_key, $message); # remote public key
		$message = xh::h2x($message);
	} elseif ($req == 'SAMLResponse' && $metadata['WantAssertionsSigned']) {
		#$message['saml:Assertion']['ds:Signature'] = sign(certs::$server_pem, $assertion);
		#$enc = docrypt(certs::$server_crt, $message['saml:Assertion'], 'saml:EncryptedAssertion');
		#$xxx = dodecrypt(certs::$server_pem, $enc);
		$message['saml:Assertion']['__t'] = 'saml:Assertion';
		$message['saml:Assertion']['ds:Signature'] = sign(certs::$server_key, $message['saml:Assertion']);
		$message = xh::h2x($message);
	} else {
		$message = xh::h2x($message);
	}
	$message = htmlspecialchars(base64_encode($message));
	print render('form', array(	'action' => $action, 'message' => $message, 'xtra' => $xtra, 'name' => $name, 'trace' => $x));
	exit;
}

function sendHTTPArtifact($message, $metadata, $artifacttype = 4) {
	if ($artifacttype == 1) $initial = pack('n', 1);
	else $initial = pack('n', 4) . pack('n', 0);
	$artifact = base64_encode($initial . sha1($message['saml:Issuer']['__v'], true) . ID());
	if ($keyfile = $GLOBALS['meta']['key']) {}; # not implemented yet ...
	newsession(sha1($artifact), 'artifact');
	$_SESSION['message'] = $message; 
	$location = $message['_Destination'] . "?SAMLArt=" . urlencode($artifact);
	$location .= $message['__']['RelayState'] ? '&RelayState=' . urlencode($message['__']['RelayState']) : "";
	$location .= $message['__']['target'] ? '&target=' . urlencode($message['__']['target']) : "";
	redirect($location);
}

function sendURI($message, $metadata) {
	$id = ID();
	newsession($id, 'assertion');
	$_SESSION['assertion'] = $message['saml:Assertion'];
	unset($message['saml:Assertion']);
	$message['saml:AssertionURIRef']['__v'] = $GLOBALS['meta']['EntityID'] . '/assertionService?ID=' . urlencode($id);
	$location .= $message['__']['RelayState'] ? '&RelayState=' . urlencode($message['__']['RelayState']) : "";
	redirect($location);
}

function sendbrowserpost($message, $metadata) {
	saml2shib($message);
	sendHTTPPost($message, $metadata);
}

function sendbrowserartifact01($message, $metadata) {
	saml2shib($message);
	sendHTTPArtifact($message, $metadata, 1);
}

function sendShibAuthnRequest($message, $metadata) {
	$location = $message['_Destination'];
	$location .= '?shire=' . urlencode($message['_AssertionConsumerServiceURL']);
	$location .= '&providerId=' . urlencode($message['saml:Issuer']['__v']);
	$location .= '&target=' . urlencode($message['_ID']);
	redirect($location, $message);
}

 function sendInternal($message, $metadata) {
	$name = $message['__']['paramname'];
	$_REQUEST['h'.$name] = $message;
	$GLOBALS['meta'] = $GLOBALS['metabase']['hosted'][$message['__']['destinationid']];
	preg_match("/([^\/]+)$/", $message['__']['destinationid'], $dollar);
	$GLOBALS['meta']['entitycode'] = $dollar[1];
	preg_match("/([^\/]+)$/", $message['_Destination'], $dollar);
	$dollar[1]();
	exit;
}

function shibSingleSignOnService() {
	$request = array(
		'__t' => 'samlp:AuthnRequest',
		'__target' => $_GET['target'],
		'_xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
		'_ID' => ID(),
		'_Version' => '1.0',
		'_IssueInstant' => $_GET['time'],
		'_AssertionConsumerServiceURL' =>  $_GET['shire'],
		'saml:Issuer' => array('__v' => $_GET['providerId']),
	);
 	$acs = $GLOBALS['metabase']['remote'][$_GET['providerId']]['AssertionConsumerService'];
 	# note to self: prepare for multi acs's in the future ...
 	if ($_GET['shire'] == $acs['Location']) $request['_ProtocolBinding'] = $acs['Binding'];	
	if (!$request['_ProtocolBinding']) sendResponse($request, createResponse($request, 'Requester'));
	$_REQUEST['hSAMLRequest'] = $request;
	singleSignOnService();
}

function saml2shib(&$message) {
	# more to come ...
	$message['_xmlns:samlp'] = 'urn:oasis:names:tc:SAML:1.0:protocol';
	$message['_xmlns:saml'] = 'urn:oasis:names:tc:SAML:1.0:assertion';
	$message['_MajorVersion'] = "1";
	$message['_MinorVersion'] = "1";
    $message['_ResponseID'] = $message['_ID'];
    $message['_Recipient'] = $message['_Destination'];
    unset($message['_Version'], $message['_ID'], $message['_Destination']);
}

function createRequest($idp, $scoping = null) {
	$remotemeta = $GLOBALS['metabase']['remote'][$idp];
	$me = $GLOBALS['metabase']['remote'][$GLOBALS['meta']['EntityID']];
	$origRequest = $_REQUEST['hSAMLRequest'];
 	$request = array(
		'__t' => 'samlp:AuthnRequest',
		'__' => array(
			'paramname' => 'SAMLRequest',
			'destinationid' => $idp,
			'ProtocolBinding' => $remotemeta['SingleSignOnService']['Binding'],
		),
		'_xmlns:saml' => 'urn:oasis:names:tc:SAML:2.0:assertion',
		'_xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
		'_ID' => ID(),
		'_Version' => '2.0',
		'_IssueInstant' => timeStamp(),
		'_Destination' => $remotemeta['SingleSignOnService']['Location'],
		'_ForceAuthn' => ($origRequest['_ForceAuthn'] == 'true') ? 'true' : 'false',
		'_IsPassive' => ($origRequest['_IsPassive'] == 'true') ? 'true' : 'false',
		'_AssertionConsumerServiceURL' =>  $me['AssertionConsumerService']['Location'],
		'_ProtocolBinding' => $me['AssertionConsumerService']['Binding'],
		'_AttributeConsumingServiceIndex' => $origRequest['_AttributeConsumingServiceIndex'],
		'saml:Issuer' => array('__v' => $GLOBALS['meta']['EntityID']),
		'ds:Signature' => '__placeholder__',
		'samlp:NameIDPolicy' => array (
			'_Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
			'_AllowCreate' => 'true',
		),
	);

	if ($scoping) {
   		$request['samlp:Scoping']['samlp:IDPList']['samlp:IDPEntry'][] = array('_ProviderID' => $scoping);
		return $request;
	}
	$request['samlp:Scoping'] = $origRequest['samlp:Scoping'];
	$request['samlp:Scoping']['_ProxyCount'] = 3;
	if ($proxyCount = $origRequest['samlp:Scoping']['_ProxyCount']) $request['samlp:Scoping']['_ProxyCount'] = $proxyCount - 1;
	$request['samlp:Scoping']['samlp:RequesterID'][] = array('__v' => $origRequest['saml:Issuer']['__v']);
	return $request;
}

function createResponse($request, $status = null, $attributes = null, $sourceresponse = null) {
	$now = timeStamp();
	$soon = timeStamp(300);
	$sessionEnd = timeStamp(60*60*12);
	$response = array (
		'__t' => 'samlp:Response',
		'__' => array(
			'paramname' => 'SAMLResponse',
			'RelayState' => $request['__']['RelayState'],
			'target' => $request['__']['target'],
		),
		'_xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
		'_xmlns:saml' => 'urn:oasis:names:tc:SAML:2.0:assertion',
		'_ID' => ID(),
		'_Version' => '2.0',
		'_IssueInstant' => $now,
		'_InResponseTo' => $request['_ID'],
		'saml:Issuer' => array('__v' => $GLOBALS['meta']['EntityID']),
		'samlp:Status' => array (
			'samlp:StatusCode' => array (
			'_Value' => 'urn:oasis:names:tc:SAML:2.0:status:Success',
			),
		),
	);
	

	$destinationid = $request['saml:Issuer']['__v'];
	$response['__']['destinationid'] = $destinationid;

	if ($acsurl = $request['_AssertionConsumerServiceURL']) {
		$response['_Destination'] 		= $acsurl;
	  	$response['__']['ProtocolBinding']	= $request['_ProtocolBinding'];
	} else {
		$remoteacs = $GLOBALS['meta']['remote'][$destinationid]['AssertionConsumerService'];
		$acsindex = $request['_AssertionConsumerServiceIndex']; # can be 0
		if ($acsindex == null) $acsindex = 'default';
		$response['_Destination'] 		= $remoteacs[$acsindex]['Location'];
	  	$response['__']['ProtocolBinding']	= $remoteacs[$acsindex]['Binding'];
	}

	if (!$response['_Destination']) die("No Destination in request or metadata for: $destinationid");

	if ($status) {
		$errorcodeprefix = 'urn:oasis:names:tc:SAML:2.0:status:';
		$response['samlp:Status'] = array(
			'samlp:StatusCode' => array (
			'_Value' => 'urn:oasis:names:tc:SAML:2.0:status:Responder',
				'samlp:StatusCode' => array (
					'_Value' => $errorcodeprefix.$status,
				),
			),
		);
		return $response;
 	}
  	
	if ($sourceresponse) {
		$response['samlp:Status'] = $sourceresponse['samlp:Status'];
		#$response['saml:EncryptedAssertion'] = $sourceresponse['saml:EncryptedAssertion'];
		$response['saml:Assertion'] = $sourceresponse['saml:Assertion'];
		$response['saml:Assertion']['saml:AuthnStatement'] = $sourceresponse['saml:Assertion']['saml:AuthnStatement'];
		$aas = &$response['saml:Assertion']['saml:AuthnStatement']['saml:AuthnContext']['saml:AuthenticatingAuthority'];
		foreach((array)$aas as $k => $aa) if ($aa['__v'] == $GLOBALS['meta']['EntityID']) unset($aas[$k]);
		if ($GLOBALS['meta']['EntityID'] != $sourceresponse['saml:Issuer']['__v'])
			$response['saml:Assertion']['saml:AuthnStatement']['saml:AuthnContext']['saml:AuthenticatingAuthority'][] = array('__v' => $sourceresponse['saml:Issuer']['__v']);
		$response['saml:Assertion']['saml:AttributeStatement'] = $sourceresponse['saml:Assertion']['saml:AttributeStatement'];
		return $response;
	}
  
	$response['saml:Assertion'] = array (
		'_xmlns:xsi' => 'http://www.w3.org/2001/XMLSchema-instance',
		'_xmlns:xs' => 'http://www.w3.org/2001/XMLSchema',
		'_xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
		'_xmlns:saml' => 'urn:oasis:names:tc:SAML:2.0:assertion',
		'_ID' => ID(),
		'_Version' => '2.0',
		'_IssueInstant' => $now,
		'saml:Issuer' => array('__v' => $GLOBALS['meta']['EntityID']),
		'ds:Signature' => '__placeholder__',
		'saml:Subject' => array (
			'saml:NameID' =>  array (
				'_SPNameQualifier' => $GLOBALS['meta']['EntityID'],
				'_Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
				'__v' => ID(),
			),
			'saml:SubjectConfirmation' => array (
				'_Method' => 'urn:oasis:names:tc:SAML:2.0:cm:bearer',
				'saml:SubjectConfirmationData' => array (
					'_NotOnOrAfter' => $soon,
					'_Recipient' => $request['_AssertionConsumerServiceURL'], # req issuer
					'_InResponseTo' => $request['_ID'],
				),
			),
		),
		'saml:Conditions' => array (
			'_NotBefore' => $now,
			'_NotOnOrAfter' => $soon,
			'saml:AudienceRestriction' => array (
				'saml:Audience' => array('__v' => $request['saml:Issuer']['__v']),
			),
		),
		'saml:AuthnStatement' => array (
			'_AuthnInstant' => $now,
			'_SessionNotOnOrAfter' => $sessionEnd,
#			'_SessionIndex' => ID(),
			'saml:SubjectLocality' => array(
				'_Address' => $_SERVER['REMOTE_ADDR'],
				'_DNSName' => $_SERVER['REMOTE_HOST'],
			),
			'saml:AuthnContext' => array (
				'saml:AuthnContextClassRef' => array('__v' => 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'),
			),
		),
	);

	$attributes['binding'][] = $response['__']['ProtocolBinding'];
	foreach((array)$attributes as $k => $vs) {
		foreach($vs as $v) {
			$attributeStatement[$k][] = $v;
		}
	}
	
	$acsi = $request['_AttributeConsumingServiceIndex'];
	$attributeStatement['AttributeConsumingServiceIndex'] = $acsi ? "AttributeConsumingServiceIndex: $acsi" : '-no AttributeConsumingServiceIndex given-';
	
	$response['saml:Assertion']['saml:AttributeStatement']['saml:Attribute'] = xh::h2a($attributeStatement);
	$xtraattrs = Array(
		'_Name' => 'xuid',
		'_NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
		'saml:AttributeValue' => Array(
			Array(
				'_xsi:type' => 'xs:string',
				'__v' => 'abc@xxx',
			),
			Array(
				'_xsi:type' => 'xs:string',
				'__v' => 'def@yyy',
			),
		),
	);
	$xtraencryptedattrs = docrypt(certs::$server_crt, $xtraattrs, 'saml:EncryptedAttribute');
	$response['saml:Assertion']['saml:AttributeStatement']['saml:EncryptedAttribute'][] = $xtraencryptedattrs;
	#$e = $response['saml:Assertion'];
	#$e['__t'] = 'saml:EncryptedAssertion';
	#$response['saml:EncryptedAssertion'] = docrypt(certs::$server_crt, $response['saml:Assertion'], 'saml:EncryptedAssertion');
	
	return $response;
}

function sign($privateKey, $element) {
	$signature = Array(
		'_xmlns:ds' => 'http://www.w3.org/2000/09/xmldsig#',
		'ds:SignedInfo' => Array(
			'ds:CanonicalizationMethod' => Array(
				'_Algorithm' => 'http://www.w3.org/2001/10/xml-exc-c14n#',
			),
			'ds:SignatureMethod' => Array(
				'_Algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
			),
			'ds:Reference' => Array(
				'_URI' => '__placeholder__',
				'ds:Transforms' => Array(
					'ds:Transform' => Array(
						'_Algorithm' => 'http://www.w3.org/2001/10/xml-exc-c14n#',
					),
				),
				'ds:DigestMethod' => Array(
					'_Algorithm' => 'http://www.w3.org/2000/09/xmldsig#sha1',
				),
				'ds:DigestValue' => Array(
					'__v' => '__placeholder__',
				),
			),
		),
	);
	
	$key = openssl_pkey_get_private($privateKey);
	$cannonicalxml = DOMDocument::loadXML(xh::h2x($element))->firstChild->C14N(true, false);;

	openssl_sign($cannonicalxml, $signatureValue, $key);
	openssl_free_key($key);
	$signature['ds:SignatureValue']['__v'] = base64_encode($signatureValue);
	$signature['ds:SignedInfo']['ds:Reference']['ds:DigestValue']['__v'] = base64_encode(sha1($cannonicalxml, TRUE));
	$signature['ds:SignedInfo']['ds:Reference']['_URI'] = "#" . $element['_ID'];
	return $signature;
}

function verify($publicKey, $xml, $element) {
	$signatureValue = $element['ds:Signature']['ds:SignatureValue']['__v'];

	$document = DOMDocument::loadXML($xml);
	$xp = new DomXPath($document); 
    $xp->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
	
	$id = $element['_ID'];
	$signedelement = $xp->query("//*[@ID = '$id']")->item(0);
	$signature = $xp->query(".//ds:Signature", $signedelement)->item(0);
	$signature->parentNode->removeChild($signature);
 	$cannonicalxml = $signedelement->C14N(true, false);

	return openssl__verify($cannonicalxml, base64_decode($signatureValue), $publicKey) == 1;
}

function docrypt($publickey, $element, $tag = null) {
	if ($tag) $element['__t'] = $tag;
	$data = xh::h2x($element);
	$cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_128,'','cbc','');
	$iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($cipher), MCRYPT_DEV_URANDOM);
	$sessionkey = mcrypt_create_iv(mcrypt_enc_get_key_size($cipher), MCRYPT_DEV_URANDOM);
	mcrypt_generic_init($cipher, $sessionkey, $iv);
	$encrypteddata = $iv . mcrypt_generic($cipher,$data);
	mcrypt_generic_deinit($cipher);
	mcrypt_module_close($cipher);

	$publickey = openssl_pkey_get_public($publickey);
    openssl_public_encrypt($sessionkey, $encryptedkey, $publickey, OPENSSL_PKCS1_PADDING);
	openssl_free_key($publickey);

	$encryptedelement = array(
		'xenc:EncryptedData' => array(
			'_xmlns:xenc' => 'http://www.w3.org/2001/04/xmlenc#',
			'_Type' =>  'http://www.w3.org/2001/04/xmlenc#Element',
			'ds:KeyInfo' => array(
				'_xmlns:ds' => "http://www.w3.org/2000/09/xmldsig#",
				'xenc:EncryptedKey' => array(
					'_Id' => ID(),
					'xenc:EncryptionMethod' => array(
						'_Algorithm' => "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
					),
					'xenc:CipherData' => array(
						'xenc:CipherValue' => array(
							'__v' => base64_encode($encryptedkey),
						),
					),
				),
			),
			'xenc:EncryptionMethod' => array (
				'_Algorithm' =>  'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
			),
			'xenc:CipherData' => array(
				'xenc:CipherValue' => array(
					'__v' => base64_encode($encrypteddata),
				),
			),
		),
	);
	return $encryptedelement;
}

function dodecrypt($privatekey, $element, $asXML = false) {
	$encryptedkey = base64_decode($element['xenc:EncryptedData']['ds:KeyInfo']['xenc:EncryptedKey']['xenc:CipherData']['xenc:CipherValue']['__v']);
	$encrypteddata = base64_decode($element['xenc:EncryptedData']['xenc:CipherData']['xenc:CipherValue']['__v']);

	$privatekey = openssl_pkey_get_private($privatekey);
    openssl_private_decrypt($encryptedkey, $sessionkey, $privatekey, OPENSSL_PKCS1_PADDING);
	openssl_free_key($privatekey);

	$cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_128,'','cbc','');
	$ivsize = mcrypt_enc_get_iv_size($cipher);
	$iv = substr($encrypteddata, 0, $ivsize);

	mcrypt_generic_init($cipher, $sessionkey, $iv);

	$decrypteddata = mdecrypt_generic($cipher, substr($encrypteddata, $ivsize));
	mcrypt_generic_deinit($cipher);
	mcrypt_module_close($cipher);	
	return $asXML ? $decrypteddata : xh::xml2hash($decrypteddata);
}

function prepareforSLO($response, $sentorreceived) {
	# save subject and sessionindex
	$_SESSION['SLO'][$sentorreceived][ID()] = $response;
};

function singleLogoutService() {
	if ($req = $_REQUEST['hSAMLRequest']) {
		# the request is active until NotOnOrAfter
	} elseif ($res = $_REQUEST['hSAMLResponse']) {
		# if success
		unset($_SESSION['SLO'][x][$_SESSION['SLOINPROCESS']][$res['_InResponseTo']]);
	
	} else die("What! No Kissing?");
	foreach($_SESSION['SLO']['received'] as $id => $response ) {
		# check for relevance for this logout request
		$_SESSION['SLOINPROCESS'][$newid] = $id;
		#send logout request to $response issuer ...
		
	}
	foreach($_SESSION['SLO']['sent'] as $response ) {
		
	
	}
	# send logoutresponse
}

function checkDestinationAudienceAndTiming() {
	$message = $_REQUEST['hSAMLRequest'] ? $_REQUEST['hSAMLRequest'] : $_REQUEST['hSAMLResponse'];
	# just use string cmp all times in ISO like format without timezone (but everybody appends a Z anyways ...)
	$skew = 60;
	$ashortwileago = timeStamp(-$skew);
	$inashortwile = timeStamp($skew);
	if ($nb = $message['saml:Assertion']['saml:Subject']['saml:SubjectConfirmation']['saml:SubjectConfirmationData']['_NotBefore'])
		if ($inashortwile < $nb)	 	$issues[] = "SubjectConfirmation not valid yet";
	if ($nooa = $message['saml:Assertion']['saml:Subject']['saml:SubjectConfirmation']['saml:SubjectConfirmationData']['_NotOnOrAfter'])
		if ($nooa < $ashortwileago) 	$issues[] = "SubjectConfirmation too old";
	if ($nb = $message['saml:Assertion']['saml:Conditions']['_NotBefore'])
		if ($inashortwile < $nb) 		$issues[] = "Assertion Conditions not valid yet";
	if ($nooa = $message['saml:Assertion']['saml:Conditions']['_NotOnOrAfter'])
		if ($nooa < $ashortwileago) 	$issues[] = "Assertions Condition too old";
	if ($snooa = $message['saml:Assertion']['saml:AuthnStatement']['_SessionNotOnOrAfter'])
		if ($snooa < $ashortwileago) $issues[] = "AuthnStatement Session too old";
	if ($destination = $message['_Destination'])
		if (strpos($GLOBALS['meta']['EntityID'], $destination) != 0) $issues[] = "Destination: '$destination' is not here";
#	if ($audience = $message['saml:Assertion']['saml:Conditions']['saml:AudienceRestriction']['saml:Audience']['__v'])
#			if ($audience !== $GLOBALS['meta']['EntityID']) $issues[] = "Assertion Conditions Audience: '$audience' is not here";

	if ($issues) die(print_r($issues,1));
	return true;
}

function infilter(&$response) {
	$metadata = $GLOBALS['metabase']['remote'][$response['saml:Issuer']['__v']];
	callattributefilter($metadata, $metadata['filter'], &$response);
	callattributefilter($GLOBALS['meta'], $GLOBALS['meta']['infilter'], &$response);
}

function outfilter(&$response) {
	callattributefilter($GLOBALS['meta'], $GLOBALS['meta']['outfilter'], &$response);
	$metadata = $GLOBALS['metabase']['remote'][$response['__']['destinationid']];
	callattributefilter($metadata, $metadata['filter'], &$response);
}

function callattributefilter($metadata, $function, &$response) {
	if (!$function) return;
	$attributes = xh::a2h($response['saml:Assertion']['saml:AttributeStatement']['saml:Attribute']);
	if (method_exists( 'userfuncs', $function)) userfuncs::$function($metadata, $response, $attributes);
	else die("userfunc::$function isn't callable");
	$response['saml:Assertion']['saml:AttributeStatement']['saml:Attribute'] = xh::h2a($attributes);
}

function redirect($location, $message = null) {
	$x = debugrequest($location, $message);
	if (!TRACE) header('Location: ' . $location);
	print <<<eoh
		<a href="$location">GO</a><br>
<pre>
$x
</pre>
eoh;
	exit;
}

function timeStamp($delta = 0) {
	return gmdate('Y-m-d\TH:i:s\Z', time() + $delta);
}

function ID() {
	return sha1(uniqid(mt_rand(), true));
}

function render($template, $vars = array(), $supertemplates = array()) { 
	if (is_array($vars)) extract($vars);  // Extract the vars to local namespace 
	else $content = $vars;
	ob_start();                    // Start output buffering 
	if (property_exists('templates', $template)) eval(templates::$$template);
	else include('templates/'.$template.'.tpl.php'); // Include the file 
	$content = ob_get_contents();  // Get the content of the buffer 
	ob_end_clean();                // End buffering and discard 
	foreach ($supertemplates as $supertemplate) 
		$content = render($supertemplate, array('content' => $content));
	return $content;               // Return the content
} 

function newsession($id, $name) {
	session_write_close();
	session_id($id);
	session_name($name);
	session_start();
}

function selfUrl($entityid = null) { return  'http' . ($_SERVER['HTTPS'] ? 's' : '') . '://' . $_SERVER['HTTP_HOST'] . selfPath($entityid);}

function selfPath($entityid = null) {
	if (!$entityid && ($id = $GLOBALS['meta']['entitycode'])) $entityid = $id;
	return $_SERVER['SCRIPT_NAME'] . '/' . ($entityid ? $entityid."/" : "");
}

function debug($name, $x, $force = false) {
	if (DEBUG || $force) file_put_contents(DEBUGLOG, "$name:\n". print_r($x, 1) . "\n+++\n", FILE_APPEND);
}

function ddebug($name, $x, $force = false) {
	if (DEBUG || $force) print "<pre>$name:\n". print_r($x, 1) . "\n+++\n</pre>";
}

function debugrequest($url, $message) {
	if (!TRACE) return;
	$displaymessage = print_r($message, 1);
	
	$displayrequest = parse_url($url);
	foreach(explode("&", $displayrequest['query']) as $p) if (preg_match("/^(.+)=(.*)$/", $p, $d))  {$rawreq[$d[1]] = urldecode($d[2]);}
	$displayrequest['query'] = $rawreq;
	
	$xmessage = htmlspecialchars(xh::h2x($message));
	return print_r($displayrequest, 1) . $xmessage . $displaymessage;
}

class xh {
	static $ns = array( 
		'urn:oasis:names:tc:SAML:1.0:protocol'		=> 'samlp',
		'urn:oasis:names:tc:SAML:1.0:assertion'		=> 'saml',
		'urn:oasis:names:tc:SAML:2.0:protocol'		=> 'samlp',
		'urn:oasis:names:tc:SAML:2.0:assertion' 	=> 'saml',
		'http://www.w3.org/2001/XMLSchema-instance' => 'xsi',
		'http://www.w3.org/2001/XMLSchema'			=> 'xs',
		'http://schemas.xmlsoap.org/soap/envelope/' => 'SOAP-ENV',
		'http://www.w3.org/2000/09/xmldsig#'		=> 'ds',
		'http://www.w3.org/2001/04/xmlenc#'			=> 'xenc',
 	);
    
	static $multivalues = array('saml:Attribute', 'saml:EncryptedAttribute', 'saml:AttributeValue',
		'samlp:IDPEntry', 'saml:AuthenticatingAuthority', 'samlp:RequesterID', 'ds:X509Certificate' );

	static function xml2hash($xml) {
	    $parser = xml_parser_create();
	    xml_parser_set_option($parser, XML_OPTION_CASE_FOLDING, 0);
    	if (xml_parse_into_struct($parser, $xml, $vals) === 1) {;
    		xml_parser_free($parser);
			$return = self::x2h($vals);
			return $return[0];
		}
		die("Error parsing incoming XML: " . xml_error_string(xml_get_error_code($parser)) . "<pre>\n" . htmlspecialchars($xml));
	}

	static function x2h(&$elements, $level = 1, $nsmap = array()) {
		$newelement = array();	
		while($val = array_shift($elements)) {
			if ($val['type'] == 'close') { 			return $newelement;
			} elseif ($val['type'] == 'cdata') { 	continue;}
			$_a = array();
			if ($a = $val['attributes']) {
				foreach($a as $k => $v) {
					unset($a[$k]);
					if (preg_match("/^xmlns:(.+)$/", $k, $d)) {
						$nsmap[$d[1]] = self::$ns[$v];
						$_a['_xmlns:'.self::$ns[$v]] = $v;
					} else {
						$_a['_'.$k] = $v;
					}
				}
			}
			$complete = array();
			$t = $val['tag'];
			if (preg_match("/^(.+):(.+)$/", $t, $d) && $prefix = $nsmap[$d[1]]) {
				$t = $prefix . ":" . $d[2];
			}
			$complete['__t'] = $t;
			if ($_a) $complete = array_merge($complete, $_a);
			if ($v = trim($val['value'])) $complete['__v'] = $v;
			if ($val['type'] == 'open') {
				$cs = self::x2h($elements, $level + 1, $nsmap);
				foreach($cs as $c) {
					$t = $c['__t'];
					unset($c['__t']);
					if (in_array($t, self::$multivalues)) {
						$complete[$t][] = $c; #$c['v'];
					} else {
						$complete[$t] = $c;
						unset($complete[$t]['__t']);
					}
				}
			} elseif ($val['type'] == 'complete') {
			} 
			$newelement[] = $complete;
		}
		return $newelement;
	}
	
	static function h2x($j, $e = "") {
		$writer = new XMLWriter(); 
		$writer->openMemory(); 
		$writer->startDocument('1.0');
		$writer->setIndent(1);
		if (!$e) $e = $j['__t'];
		self::h2xinner($j, $e, $writer);
		$writer->endDocument(); 
		return $writer->outputMemory(); 
	}
	
	static function h2xinner($j, $e, $writer) {
		if ($j == '__placeholder__') return;
		if (!$j[0]) $writer->startElement($e);
		foreach((array)$j as $k => $v) {
			if (is_int($k)) { 					self::h2xinner($v, $e, $writer); 
			} elseif ($k == '__v') {			$writer->text($v);
			} elseif (strpos($k, '__') === 0){	# [__][<x>] is used for private attributes for internal consumtion
			} elseif (strpos($k, '_') === 0){  	$writer->writeAttribute(substr($k, 1), $v);
			} else {							self::h2xinner($v, $k, $writer); }
		}
		if (!$j[0]) $writer->endElement();
	}
	
	static function a2h($attrs) {
		foreach((array)$attrs as $attr) {
			foreach ($attr['saml:AttributeValue'] as $val) { 
				$res[$attr['_Name']][] = $val['__v'];
			}
		}
		return $res;
	}
	
	static function h2a($attrs) {
		foreach((array)$attrs as $name => $attr) {
			$newattr = array(
				'_Name' => $name,
				'_NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
			);
			foreach ((array)$attr as $val) {
				$newattr['saml:AttributeValue'][] = array (
				   '_xsi:type' => 'xs:string',
				   '__v' => $val,
				);
			}
			$res[] = $newattr;
		}
		return $res;
	}
}

class userfuncs {

	static function idpfilter($metadata, $message, &$attributes) {
		$attributes['xxx'][] = 'idpfilter@' . $metadata['EntityID'] . ' from ' . $message['saml:Issuer']['__v'];
	}
	
	static function infilter($metadata, $message, &$attributes) {
		$attributes['xxx'][] = 'infilter@' . $metadata['EntityID'];
		$attributes['zzz'][] = '<tag>what!</tag><tag what="no!" />';
	}

	static function outfilter($metadata, $message, &$attributes) {	
		$attributes['xxx'][] = 'outfilter@' . $metadata['EntityID'];
	}
	
	static function spfilter($metadata, $message, &$attributes) {
		$attributes['xxx'][] = 'spfilter@' . $metadata['EntityID'] . ' to ' . $message['__']['destinationid'];
	}
	
	static function nullSingleSignonService() {
		if ($_POST['pw'] && $_POST['uid']) {
			$request = $_SESSION[$_POST['ID']]['hSAMLRequest'];
			$response = createResponse($request, null, array('uid' => array('abc@'.$GLOBALS['meta']['entitycode'])));
			unset($_SESSION[$_POST['ID']]);
			if ($GLOBALS['meta']['keepsession']) {
				$_SESSION['CachedResponses'][$response['saml:Issuer']['__v']] = $response;
				#$_SESSION['CachedIDP'] = $response['saml:Issuer']['__v'];
			}
			sendResponse($request, $response);
		} else {
			if ($_REQUEST['hSAMLRequest']['_IsPassive'] == 'true') sendResponse($_REQUEST['hSAMLRequest'], createResponse($_REQUEST['hSAMLRequest'], 'NoPassive'));
			$id = $_REQUEST['hSAMLRequest']['_ID'];
			$_SESSION[$id]['hSAMLRequest'] = $_REQUEST['hSAMLRequest'];
			$action = selfUrl() . 'nullSingleSignonService';
			print render('null', array('action' => $action, 'ID' => $id));
		}
		exit;
	}
}

class templates {

public static $null ='?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
        "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
	<title>Null Auth</title>
</head>
<body>
<form method="post" action="<?= $action ?>">
Just click "OK" for standard authentication.
<input type=hidden name=ID value="<?= $ID ?>">
<input type=hidden name=pw value=abc>
<input type=hidden name=uid value=abc>
<input type=submit value="OK">
</form>
</body>
</html>
<?';

public static $consent = '?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
        "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
	<title>Discover ...</title>
</head>
<body>
<form method="post" action="<?= $action ?>">
<input type=hidden name=ID value="<?= $ID ?>">
C: <?= $c ?>
Vil du virkelig sende følgende:
<pre>
<? print_r($attributes) ?>
</pre>
<input type=submit value=Send>
</form>
</body>
</html>
<?';

public static $discover = '?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
        "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
	<title>Discover ...</title>
</head>
<body>
<form method="post" action="<?= $action ?>">
<input type=hidden name=ID value="<?= $ID ?>">
<select name=idp>
<? foreach($idpList as $idp): ?>
<option><?= $idp ?></option>
<? endforeach ?>
</select>
<input type=submit value=Send>
</form>
</body>
</html>
<?';

public static $form = '?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<title>POST data</title>
</head>
<? if (!$trace): ?><body onload="document.forms[0].submit()"><? endif; ?>
<noscript>
<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>
</noscript>
<form method="post" action=" <?= $action ?>">
<input type="hidden" name="<?= $name ?>" value="<?= $message ?>" />
<?= $xtra ?>
<noscript><input type="submit" value="Submit" /></noscript>
<? if ($trace): ?>
<input type="submit" value="Submit" />
<pre>
<?= $trace ?>
</pre>
<? endif; ?>

</form>
</body>
</html>
<?';

public static $demo = '?>
<html><head>
<style type="text/css" title="text/css">
<!--
body {
	color: #CC9933;
	background-color: #FFFFCC;
	font-size: large;
	font-family: verdana,monospace;
	text-align: left;
}

pre {
	font-size: medium;
}

table { padding: 1ex; }
td.r
{
	text-align: right;
	vertical-align: top;
}
div {
	border: 1px dotted;
	margin: 1em;
	padding: 1em;
	width: 55em;
}
a:link, a:visited, a:hover, a:active {
	text-decoration: none;
	color: #CC9933;
}
-->
</style>
</head>
<body>
<div>
<p><?= $message ?>
<form method=POST action="<?= $action ?>">
	<input name=doit value=1 type=hidden>
	<? foreach($idps as $idp): ?>
		<input type=checkbox name="IDPList[]" value="<?= $idp ?>"><?= $idp?> <br>
	<? endforeach; ?>
	<input type=checkbox name="idp"  checked value="wayf_idp1">Idp1 via wayf<br>
	<input type=checkbox name="idp" value="wayf_idp2">Idp2 via wayf<br>
	<input type=checkbox name="idp" value="idp1">Idp1 directly<br>
	<input type=checkbox name=IDPList[]  value="http://jach-idp.test.wayf.dk/saml2/idp/metadata.php">jach-idp<br>
	<input type=checkbox name=IDPList[]  value="https://pure.wayf.ruc.dk/myWayf">pure-idp<br>
	<p>
	<input type=checkbox name=ForceAuthn value=true>ForceAuthn</p>
	<input type=checkbox name=IsPassive value=true>IsPassive</p>
	<a href="<?= $self . "/wayf/shibSingleSignOnService?shire=" . urlencode($self) . "/main/demoapp&providerId=" . urlencode($self) . "/main" ?>">Shibboleth</a><p>
	<input type=submit value="Send Request">
</form>
<pre>
<?= preg_replace("/\n\n/", "\n", preg_replace("/Array\n\s+/", "Array ", htmlspecialchars(print_r($hSAMLResponse, 1)))); ?>
</pre>
</div>
</body>
</html>
<?';
}

class Demo {

	public static function sendAttributeQuery($aa = 'https://wayf.ruc.dk/els/s/springfika.php/main/attributeService') {
		$attributeQuery = array(
			'samlp:AttributeQuery' => array(
				'_xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
				'_xmlns:saml' => 'urn:oasis:names:tc:SAML:2.0:assertion',
				'_ID' => ID(),
				'_Version' => '2.0',
				'_IssueInstant' => timeStamp(),
				'saml:Artifact' => array('__v' => $_REQUEST['SAMLArt']),
				'saml:Issuer' => array('__v' => $GLOBALS['meta']['EntityID']),
			),
		);
		$assertion = soapRequest($aa, $attributeQuery);
		print_r($assertion);
	}
	
	public static function demoapp() {
		$sharedkey = 'abracadabra';
	
		$self = 'http' . ($_SERVER['HTTPS'] ? 's' : '') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME'];
		if ($_POST['doit']) {
			$idp = $_POST['idp'];
			if (!$idp) $idp = "wayf";
			$request = array(
				'_ID' => sha1(uniqid(mt_rand(), true)),
				'_Version' => '2.0',
				'_IssueInstant' => gmdate('Y-m-d\TH:i:s\Z', time()),
				'_Destination' => $self . "/$idp/singleSignOnService",
				'_ForceAuthn' => $_REQUEST['ForceAuthn'] ? 'true' : 'false',
				'_IsPassive' => $_REQUEST['IsPassive'] ? 'true' : 'false',
				'_AssertionConsumerServiceURL' => $self . "/main/" . __FUNCTION__,
				'_AttributeConsumingServiceIndex' => 5,
				'_ProtocolBinding' => 'JSON-POST',
				'saml:Issuer' => array('__v' => $self . "/main"),
			);
			
			foreach((array)$_REQUEST['IDPList'] as $idp) $idplist[] = array('_ProviderID' => $idp);
			
			$relaystate = 'Dummy RelayState ...';
			if ($idplist) $request['samlp:Scoping']['samlp:IDPList']['samlp:IDPEntry'] = $idplist;
			$request['samlp:Scoping']['_ProxyCount'] = 2;
			$location = $request['_Destination'];
			$request = "jSAMLRequest=" . urlencode(base64_encode(gzdeflate(json_encode($request)))) 
				. ($relaystate ? '&RelayState=' . urlencode($relaystate) : '');
			$signature = urlencode(base64_encode(sha1($sharedkey . sha1($request))));
			header('Location: ' . $location . "?" . $request . "&Signature=" . $signature);
		print <<<eoh
			<a href="$location?$request&Signature=$signature">$location</a>
eoh;
			exit;
		}

		$response = base64_decode($_POST['jSAMLResponse']);
		$hSAMLResponse = json_decode($response, 1);
		if ($rs = $_POST['RelayState']) $rs = '&RelayState=' . $rs;
		if (base64_encode(sha1($sharedkey . sha1("jSAMLResponse=$response$rs"))) != $_POST['Signature']) $message = 'Integrity check failed (Sharedkey)';
		
		print render(demo, array(	'action' => $self . "/main/demoapp",
									'idps' => array_keys($GLOBALS['metabase']['remote']),
									'hSAMLResponse' => $hSAMLResponse,
									'message' => $message . " RelayState: " . $_GET['RelayState'],
									'self' => $self));
	}
	

}

class certs {
	public static $server_crt = 
'-----BEGIN CERTIFICATE-----
MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMC
Tk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYD
VQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG
9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4
MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xi
ZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2Zl
aWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5v
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LO
NoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHIS
KOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d
1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8
BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7n
bK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2Qar
Q4/67OZfHd7R+POBXhophSMv1ZOo
-----END CERTIFICATE-----
';

	public static $server_key = 
'-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9
IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+
PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQAB
AoGAD4/Z4LWVWV6D1qMIp1Gzr0ZmdWTE1SPdZ7Ej8glGnCzPdguCPuzbhGXmIg0V
J5D+02wsqws1zd48JSMXXM8zkYZVwQYIPUsNn5FetQpwxDIMPmhHg+QNBgwOnk8J
K2sIjjLPL7qY7Itv7LT7Gvm5qSOkZ33RCgXcgz+okEIQMYkCQQDzbTOyDL0c5WQV
6A2k06T/azdhUdGXF9C0+WkWSfNaovmTgRXh1G+jMlr82Snz4p4/STt7P/XtyWzF
3pkVgZr3AkEA7nPjXwHlttNEMo6AtxHd47nizK2NUN803ElIUT8P9KSCoERmSXq6
6PDekGNic4ldpsSvOeYCk8MAYoDBy9kvVwJBAMLgX4xg6lzhv7hR5+pWjTb1rIY6
rCHbrPfU264+UZXz9v2BT/VUznLF81WMvStD9xAPHpFS6R0OLghSZhdzhI0CQQDL
8Duvfxzrn4b9QlmduV8wLERoT6rEVxKLsPVz316TGrxJvBZLk/cV0SRZE1cZf4uk
XSWMfEcJ/0Zt+LdG1CqjAkEAqwLSglJ9Dy3HpgMz4vAAyZWzAxvyA1zW0no9GOLc
PQnYaNUN/Fy2SYtETXTb0CQ9X1rt8ffkFP7ya+5TC83aMg==
-----END RSA PRIVATE KEY-----
';
	public static $wayfwildcard =
'-----BEGIN CERTIFICATE-----
MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMC
Tk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYD
VQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG
9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4
MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xi
ZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2Zl
aWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5v
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LO
NoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHIS
KOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d
1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8
BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7n
bK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2Qar
Q4/67OZfHd7R+POBXhophSMv1ZOo
-----END CERTIFICATE-----
';
}
