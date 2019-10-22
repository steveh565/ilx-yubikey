// Author: Brett Smith @f5
// index.js for yubikey_auth_apm_event_lx

// Includes
var f5 = require('f5-nodejs');
var yub = require('yub');
 
// Create a new rpc server for listening to TCL iRule calls.
var ilx = new f5.ILXServer(); 
 
// Start listening for ILX::call and ILX::notify events.
ilx.listen();

// YubiKey Auth
ilx.addMethod('yubikey_auth', function(yubiotp, response) {

    // Get a Yubico Client ID and API Key from here: https://upgrade.yubico.com/getapikey/
    var client_id = 'XXXX';
    var secret_key = 'XXXXXXXXXXXXXXX';

    // Initialise the yub library
    yub.init(client_id, secret_key);

    // Attempt to verify the OTP
    yub.verify(yubiotp.params()[0], function(err,data) {
        if (err) {
            console.log('Error: YubiKey OTP Verify Failed!');
            response.reply('valid 0');
        } else {
            response.reply(data);
        }
    });
});