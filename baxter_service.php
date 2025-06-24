<?php 

/***** BAXTER BOT MANAGEMENT *****/
/* Author: Ethan Gruber, egruber@numismatics.org
 * Date Modified: June 2025
 * Requirements: Linux sendmail (for php mail()), php-curl
 * Function: this script can be run as a service in a Linux setting. 
 * See https://tecadmin.net/running-a-php-script-as-systemd-service-in-linux/
 */

include('baxter.php');

if ($valid == true) {
    // Set the script to run indefinitely
    while (true) {
        
        initiate_process($ignore_ips, $ignore_bots);
        
        echo "Process completed. Waiting " . INTERVAL . " seconds.\n";

        sleep(INTERVAL);
    }
} else {
    echo "Baxter configuration invalid. Recheck CONST values.\n";
}

?>