<h1>Sample App with VIP API integration using Node.js</h1>

<h2>Introduction</h2>

Demonstration Node.js app for Symantec VIP. Shows inline 
registration of VIP credential.

<h2>Prerequisites</h2>                                                          

Install Node.js - https://nodejs.org                    

Install the Node dependencies

- npm install express                                   
- npm install express-session                           
- npm install body-parser                               
- npm install soap

<h2>Configuration</h2>

Configure your VIP certificate                          

- Create a subdirectory called "certs"
- Download a VIP certificate P12 from VIP Manager to the certs directory       
- Update config section of vipdemo.js with your P12 password        

<h2>Operation</h2>

Start the Node.js service

- node vipdemo.js                                       

Point your browser at http://localhost:3000 (or whichever port you have 
configured).

Log in with one of the test userid/passwords in the configuration section.

If the user is found in VIP, and has a credential registered, you will be
prompted for an OTP.

If the user is not found in VIP, or has no registered credentials, then 
the user is prompted to register their credential. The user is then added
to VIP (if not already) and the credential is registered to the user.