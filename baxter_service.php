<?php 

/***** BAXTER BOT MANAGEMENT *****/
/* Author: Ethan Gruber, egruber@numismatics.org
 * Date Modified: June 2025
 * Requirements: Linux sendmail (for php mail()), php-curl
 * Function: this script can be run as a service in a Linux setting. 
 * See https://tecadmin.net/running-a-php-script-as-systemd-service-in-linux/
 */

include('baxter.php');

while (true) {
    
    $valid = validate_config();
    
    if ($valid == true) {
        initiate_process($ignore_ips, $ignore_bots);
        
        echo "Process completed. Waiting " . INTERVAL . " seconds.\n";
    } else {
        echo "Baxter configuration invalid. Recheck CONST values or API_KEY has reached limit.\n";
    }
    
    sleep(INTERVAL);
}

?>