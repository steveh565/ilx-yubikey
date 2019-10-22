# Author: Brett Smith @f5

when RULE_INIT {
    # Debug logging control.
    # 0 = debug logging off, 1 = debug logging on.
    set static::yubikey_debug 0
}
 
when ACCESS_POLICY_AGENT_EVENT {
    if { [ACCESS::policy agent_id] eq "yubikey_auth" } {
        # Get the YubiKey OTP from APM session data
        set yubiotp [ACCESS::session data get session.logon.last.yubiotp]
        if { $static::yubikey_debug == 1 }{ log local0. "YubiKey OTP: $yubiotp" }
 
        # Basic error handling - don't execute Node.JS if session.logon.last.yubiotp is null   
        if { ([string trim $yubiotp] eq "") } {
            # The YubiKey OTP is not valid
            ACCESS::session data set session.yubikey.valid 0
            if { $static::yubikey_debug == 1 }{ log local0. "YubiKey OTP is not valid!" }
        } else {
            # Initialise the iRulesLX extension
            set rpc_handle [ILX::init yubikey_auth_extension]
       
            # Need to change the default RPC timeout from 3 sec to 30 sec to 
            # allow for the HTTPS request to the Yubico API
            set timeout 30000
           
            # Pass the YubiKey OTP to Node.JS and save the iRulesLX response
            set rpc_response [ILX::call $rpc_handle -timeout $timeout yubikey_auth $yubiotp]
            if { $static::yubikey_debug == 1 }{ log local0. "rpc_response: $rpc_response" }
            
            # Loop through each key/value pair returned from "yub.verify"
            foreach {key value} $rpc_response {
                # Assign the key/value pair to an APM session variable so it 
                # can be referenced in the Access Policy
                ACCESS::session data set session.yubikey.$key $value
                if { $static::yubikey_debug == 1 }{ log local0. "$key $value" }
            }
        }
    }
}