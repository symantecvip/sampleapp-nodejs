/**************************************************************/
/*                                                            */
/* vipdemo.js                                                 */
/*                                                            */
/* Demonstration Node.js app for Symantec VIP                 */
/*                                                            */
/**************************************************************/


/**************************************************************/
/*                                                            */
/* Config                                                     */
/*                                                            */
/**************************************************************/

// Debug mode
var debug = false;

// Port to listen on
var port           = 3000;

// VIP WSDL files
var queryWsdlUrl   = 'wsdl/vipuserservices-query-1.8.wsdl';
var authWsdlUrl    = 'wsdl/vipuserservices-auth-1.8.wsdl';
var mgmtWsdlUrl    = 'wsdl/vipuserservices-mgmt-1.8.wsdl';

// VIP Certificate location and password
var clientCert     = 'certs/vip_cert.p12';
var clientCertPass = 'Password1';

// Test users

var testPasswords = { "jane.doe" : "Passw0rd",
                      "john.doe" : "Passw0rd",
                      "brian.doe" : "Passw0rd",
                      "mighty.mouse" : "Passw0rd" }

/**************************************************************/
/*                                                            */
/* Constants                                                  */
/*                                                            */
/**************************************************************/

var VERSION                 = '1'

var VIP_STATUS_OK           = "0000";
var VIP_STATUS_USERNOTEXIST = "6003";
var VIP_STATUS_AUTHFAILED   = "6009";

/**************************************************************/
/*                                                            */
/* Dependencies                                               */
/*                                                            */
/**************************************************************/

var express = require('express'),
    app = express(),
    session = require('express-session');

var bodyParser = require('body-parser');

var soap = require('soap');

/**************************************************************/
/*                                                            */
/* Initialisation                                             */
/*                                                            */
/**************************************************************/

// Session

app.use(session({
    secret: '2C44-4D44-WppQ38S',
    resave: true,
    saveUninitialized: true
}));

// parse application/json
app.use(bodyParser.json());

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));


// SOAP clients

var clientSecurity = new soap.ClientSSLSecurityPFX(
  	  clientCert,
	  clientCertPass
);

// Query client

var vipQueryClient = null;

soap.createClient(queryWsdlUrl, function(err, client) {
	if (err)
	{
	  console.log(err);
	}
    client.setSecurity(clientSecurity);
    vipQueryClient = client;

});


// Management client

var vipMgmtClient = null;

soap.createClient(mgmtWsdlUrl, function(err, client) {
	if (err)
	{
	  console.log(err);
	}
    client.setSecurity(clientSecurity);
    vipMgmtClient = client;

});


// Authentication client

var vipAuthClient = null;

soap.createClient(authWsdlUrl, function(err, client) {
	if (err)
	{
	  console.log(err);
	}
    client.setSecurity(clientSecurity);
    vipAuthClient = client;

});


/**************************************************************/
/*                                                            */
/* Functions                                                  */
/*                                                            */
/**************************************************************/

// logging

function soapLog(operation,client, err, result)
{
	if (!debug) return;

	console.log("-----------------------------------------------------");
	console.log("SOAP command [" + operation + "]");
	console.log("-----------------------------------------------------");
	console.log("-> Sent");
	console.log("-----------------------------------------------------");
	console.log(client.lastRequest);
	console.log("-----------------------------------------------------");
	console.log("<- Received");
	console.log("-----------------------------------------------------");
	console.log(result);
	console.log("-----------------------------------------------------");

}


// Authentication and Authorization Middleware

var auth = function(req, res, next) {
  if (req.session && req.session.loggedin)
  {
    return next();
  }
  else
  {
      res.writeHead(302, {'Location': '/login'});
      res.end();
  }
};

// First factor authentication

function authenticatePassword(userid,password)
{
	console.log("authenticating first factor")
	var pass = testPasswords[userid];
	return (pass && pass === password);
}

// Second factor authentication. If user exists and has registered
// credential, prompt for OTP. Otherwise prompt for token registration

function challengeOrRegisterVIP(userid, req, res)
{
	var registered = false;

    var args = {requestId: '1234567890',
                userId: userid };

	vipQueryClient.getUserInfo(args, function(err, result) {
		soapLog("getUserInfo",vipQueryClient,err,result);

        // If we found the user, and they have credential(s) registered
        // prompt for OTP

		if (result.status === VIP_STATUS_OK &&
		    result.numBindings != 0)
		{
			res.send(
				'Please enter your VIP security code<br/><br/>' +
				'<form action="/viphandler" method="post">'+
				'<table>' +
				'<tr><td>Security Code</td><td><input type="text" name="otp"></td></tr>'+
				'<tr><td colspan="2" align="right"><input type="submit" name="cancel" value="Cancel"><input type="submit" value="OK"></td></tr>'+
				'</table>' +
				'</form>'
			);
		}

		// The user doesn't exist, so send them off to get registered

		else
		{
			req.session.existinguser = (result.status === VIP_STATUS_OK);

			res.send(
				'Please register your VIP token<br/><br/>' +
				'<form action="/vipregister" method="post">'+
				'<table>' +
				'<tr><td>Serial Number</td><td><input type="text" name="serial"></td></tr>'+
				'<tr><td>Friendly Name</td><td><input type="text" name="name"></td></tr>'+
				'<tr><td>Security Code</td><td><input type="text" name="otp"></td></tr>'+
				'<tr><td colspan="2" align="right"><input type="submit" name="cancel" value="Cancel"><input type="submit" value="Register"></td></tr>'+
				'</table>' +
				'</form>'
			);
		}

  	});

}

// Perform validation of OTP

function authenticateVIP(userid,securitycode,req,res)
{
    var args = {requestId: '1234567890',
                userId: userid,
                otpAuthData: { otp: securitycode }};

	vipAuthClient.authenticateUser(args, function(err, result)
	{
		soapLog("authenticateUser",vipAuthClient,err,result);
        if (result.status === VIP_STATUS_OK)
        {
			req.session.user = userid;
			req.session.loggedin = true;
			res.writeHead(302, {'Location': '/'});
			res.end();
		}
		else
		{
			challengeOrRegisterVIP(userid, req, res);
		}

  	});
}

// Register a user with the VIP service

function registerVIP(userid,serial,name,securitycode,req,res)
{
	// If the user exists in VIP, just register credential
	if (req.session.existinguser)
	{
		registerCredential(userid,serial,name,securitycode,req,res);
	}
	// If user does not exist, then add user, then register credential
	else
	{
		var args = {requestId: '1234567890',
					userId: userid };

		vipMgmtClient.createUser(args, function(err, result)
		{
			soapLog("createUser",vipMgmtClient, err, result);

			if (result.status === VIP_STATUS_OK)
			{
				registerCredential(userid,serial,name,securitycode,req,res);
			}
			else
			{
				res.send("error");
			}

		});
	}
}

// Register a credential to an existing user

function registerCredential(userid,serial,name,securitycode,req,res)
{
    var args = {requestId: '1234567890',
                userId: userid,
                credentialDetail: { credentialId: serial,
                                    credentialType: "STANDARD_OTP",
                                    friendlyName: name

                                  },
                 otpAuthData: { otp: securitycode }
                };

	vipMgmtClient.addCredential(args, function(err, result)
	{
		soapLog("addCredential",vipMgmtClient,err,result);

		if (result.status === VIP_STATUS_OK)
		{
			req.session.loggedin = true;
			res.writeHead(302, {'Location': '/'});
			res.end();

		}
		else
		{
			  challengeOrRegisterVIP(userid, req, res);
		}

	});
}

/**************************************************************/
/*                                                            */
/* Endpoints                                                  */
/*                                                            */
/**************************************************************/

// Home page only accessible to authenticated users

app.get('/', auth, function (req, res) {
    res.send("Welcome to the secure site. <a href='/logout'>Logout</a>");

});

// Login page - user always redirected here when not logged in

app.get('/login', function (req, res) {
	console.log("rendering login page");
	res.writeHead(200, {'content-type': 'text/html'});
	  res.end(
		'Please log in<br/><br/>' +
		'<form action="/loginhandler" method="post">'+
		'<table>' +
		'<tr><td>Userid</td><td><input type="text" name="userid"></td></tr>'+
		'<tr><td>Password</td><td><input type="password" name="password"></td></tr>'+
		'<tr><td colspan="2" align="right"><input type="submit" value="Login"></td></tr>'+
		'</table>' +
		'</form>'
	  );
});


// Login handler - first factor authentication

app.post('/loginhandler', function (req, res) {
	console.log("processing login");
  if (!authenticatePassword(req.body.userid,req.body.password))
  {
	res.writeHead(302, {'Location': '/'});
	res.end();
  }
  else
  {
	  req.session.userid = req.body.userid;
	  challengeOrRegisterVIP(req.body.userid, req, res);
  }
});

// VIP handler - second factor authentication

app.post('/viphandler', function (req, res) {

  if (req.body.cancel)
  {
	  res.writeHead(302, {'Location':'/logout'});
	  res.end();
  }
  else
  {
    authenticateVIP(req.session.userid,req.body.otp,req,res);
  }
});

// VIP registration

app.post('/vipregister', function (req, res) {
  if (req.body.cancel)
  {
	  res.writeHead(302, {'Location':'/logout'});
	  res.end();
  }
  else
  {
  	registerVIP(req.session.userid,req.body.serial,req.body.name,req.body.otp,req,res);
  }

});

// Logout

app.get('/logout', function (req, res) {
	req.session.destroy();
	res.writeHead(302, {'Location': '/'});
	res.end();
});



/**************************************************************/
/*                                                            */
/* Go                                                         */
/*                                                            */
/**************************************************************/

app.listen(port);
console.log("vipdemo v" + VERSION + " running at http://localhost:" + port);