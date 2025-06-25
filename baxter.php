<?php 

/***** BAXTER BOT MANAGEMENT *****/
/* Author: Ethan Gruber, egruber@numismatics.org
 * Date Modified: June 2025
 * Requirements: Linux sendmail (for php mail()), php-curl
 */

define("API_KEY", ""); //get API key from https://www.abuseipdb.com/ . The free account of 1,000 per day is good enough for testing
define("ENV", "DEV"); //DEV and PROD are the only acceptable values
define("INTERVAL", 300); //default interval is 300 second between analyses
define("CLUSTER_MINIMUM", 35); //recommend starting at 35 for cluster to re-running manually to 20 or 15 to cull worst offenders before running baxter as a service
define("WATCHLIST_BAN", 4); //if the IP address range has reached WATCHLIST_BAN (default: 4) times on the weekly watchlist, add it to the banned list
define("LOGFILE", "/var/log/apache2/access*.log");
define("EMAIL", "");

$ignore_ips = array('18.191.94.77');
$ignore_bots = array('googlebot','bingbot','yandex','duckduckgo', 'slurp');


/***** COMMENT OUT THE FOLLOWING WHEN RUNNING AS A SERVICE *****/
$valid = validate_config();

//if the config is valid, then begin the process
if ($valid == true) {
    initiate_process($ignore_ips, $ignore_bots);
} else {
    echo "Baxter configuration invalid. Recheck CONST values.\n";
}

/***** FUNCTIONS *****/
//function to initiate the reading of log files and constructing an arrays of IP addresses and the volume of usage
function initiate_process ($ignore_ips, $ignore_bots) {    
    
    $currentTime = time();
    $timeAgo = $currentTime - INTERVAL;
    $currentDate = date('Y-m-d', $currentTime);
    $dateAgo = date('Y-m-d', $timeAgo);
    
    //if 5 minutes ago was actually yesterday, then either send report or drop all IPs from iptables again
    if ($currentDate != $dateAgo) {    
        //send daily reports only if email address is defined
        if (defined('EMAIL') && strlen(EMAIL) > 0) {
            email_report($dateAgo);
            
            echo "Removing yesterday's log files\n";
            unlink('allowed_ips');
            unlink('flagged_ips');
            unlink('banned_ips');
            //note: watchlist should be removed weekly by cron so that watchlisted IP ranges are examined for repeated requests across days in a week
        } else {
            $banned_ips = fopen("banned_ips", "r") or die("Unable to create or open banned_ips");
            while (($line = fgets($banned_ips, 4096)) !== false) {
                $ip = trim($line);
                if (ENV == "PROD") {
                    shell_exec("/sbin/iptables -I INPUT -s {$ip} -j DROP");
                }                    
            }
            fclose($banned_ips);                
        }
    }    
    
    //create allowed and banned ip file lists to prevent repetitive API calls
    $allowed_ips = fopen("allowed_ips", "a+") or die("Unable to create or open allowed_ips");
    $flagged_ips = fopen("flagged_ips", "a+") or die("Unable to create or open flagged_ips");
    $banned_ips = fopen("banned_ips", "a+") or die("Unable to create or open banned_ips");
    $watchlist = fopen("watchlist", "a+") or die("Unable to create or open watchlist");
    
    //an array of IP addresses and ranges from the Baxter log files, which were already processed
    $processed_ips = array();
    
    while (($line = fgets($allowed_ips, 4096)) !== false) {
        $processed_ips[] = trim($line);
    }
    while (($line = fgets($flagged_ips, 4096)) !== false) {
        $processed_ips[] = trim($line);
    }
    while (($line = fgets($banned_ips, 4096)) !== false) {
        $processed_ips[] = trim($line);
    }
    
    //create new array for Apache log file(s) IP addresses
    $ips = parse_log_files($ignore_ips, $ignore_bots);
    
    //sort by count and issue report. Superusers constitute top 0.2 percentile
    arsort($ips);
    process_superusers ($ips, $allowed_ips, $flagged_ips, $banned_ips, $processed_ips);
    
    //sort by keys and prepare for further processing
    ksort($ips);
    process_clusters ($ips, $allowed_ips, $flagged_ips, $banned_ips, $processed_ips, $watchlist, $currentTime);
    
    fclose($allowed_ips);
    fclose($flagged_ips);
    fclose($banned_ips);
    fclose($watchlist);
}

/***** READ LOG FILES INTO IPS ARRAY *****/
function parse_log_files ($ignore_ips, $ignore_bots) {
    $ips = array();    
    $files = glob(LOGFILE);    
    
    //allowing for wildcards, parse each Apache logfile to return an array of IP addresses and number of occurrences
    foreach ($files as $file) {
        $handle = fopen($file, "r");        
        if ($handle) {
            while (($line = fgets($handle, 4096)) !== false) {
                preg_match('/(^\d+\.\d+\.\d+\.\d+)\s/', $line, $matches);
                $allowed_bot = false;
                
                //suppress any IP address that matches an allowable search robot user agent
                foreach ($ignore_bots as $bot) {
                    if (strpos(strtolower($line), $bot) !== FALSE) {
                        $allowed_bot = true;
                        break;
                    }
                }
                
                if (isset($matches[1]) && $allowed_bot == false) {
                    $ip = trim($matches[1]);
                    
                    //process any IP address which is not explicitly ignored
                    if (!in_array($ip, $ignore_ips)) {
                        if (!array_key_exists($ip, $ips)) {
                            $ips[$ip] = 1;
                        } else {
                            $ips[$ip] = $ips[$ip] + 1;
                        }
                    }
                }
            }
            
            fclose($handle);
        } else {
            echo "Unable to open {$file}\n";
        }
    }
    
    return $ips;
}

/***** PROCESS SUSPICIOUS IP RANGE CLUSTERS *****/
function process_clusters ($ips, $allowed_ips, $flagged_ips, $banned_ips, $processed_ips, $watchlist, $currentTime) {
    
    //the cluster array creates a key for each prefix and the unique IDs part of that cluster so that they can be counted
    $sorted = array();
    $cluster = array();
    
    //presort the entire array of prefixes and IP addresses; simplifies testing
    foreach ($ips as $ip=>$count) {
        $pieces = explode('.', $ip);
        
        $prefix = $pieces[0] . '.' . $pieces[1] . '.' . $pieces[2];
        
        if (!array_key_exists($prefix, $sorted)) {
            $sorted[$prefix] = array();
            $sorted[$prefix][] = $ip;
        } else {
            if (!in_array($ip, $sorted[$prefix])) {
                $sorted[$prefix][] = $ip;
            }
        }
    }
    
    foreach ($sorted as $prefix=>$arr) {        
        //threshold of 15 IPs per prefix:
        if (count($arr) >= CLUSTER_MINIMUM) {
            $cluster[$prefix] = $arr;
        }
    }
    
    echo "Processing " . count($cluster) . " clusters with a minimum of " . CLUSTER_MINIMUM . " IP addresses\n";
    
    if (ENV == "DEV") {
        //insert any necessary logic to test cluster processing here        
        $test = 50;    
        
        $cluster = array_slice($cluster, $test, 2, true);        
        
        foreach ($cluster as $prefix=>$arr) {
            analyze_cluster ($prefix, $arr, $allowed_ips, $flagged_ips, $banned_ips, $processed_ips, $watchlist, $currentTime);
        }
    } elseif (ENV == "PROD") {
        foreach ($cluster as $prefix=>$arr) {
            analyze_cluster ($prefix, $arr, $allowed_ips, $flagged_ips, $banned_ips, $processed_ips, $watchlist,  $currentTime);
        }
    } else {
        echo "process_clusters() error: ENV constant not set properly. Values must be DEV or PROD.\n";
    }
}

function analyze_cluster ($prefix, $arr, $allowed_ips, $flagged_ips, $banned_ips, $processed_ips, $watchlist, $currentTime) {
    $notation = $prefix . '.0/24';
    
    //if the prefix has already been checked, skip it
    if (!in_array($notation, $processed_ips)) {
        $index = 0;
        $badbots = 0;
        $flaggedbots = 0;
        //var_dump($arr);
        
        //submit API calls for the first 9 IP addresses in the array of 15+
        while ($index < 9) {
            $ip = $arr[$index];
            //get JSON from Abuse IPDB API
            $json = lookup_ip($ip);
            
            if (isset($json->data->abuseConfidenceScore)) {
                $score = $json->data->abuseConfidenceScore;
                
                //echo "{$ip}: {$json->data->totalReports}\n";
                
                if ($score > 0) {
                    //if there is any abuseConfidenceScore at all, count it as a bad bot
                    echo "Bad bot: {$ip} ({$score})\n";
                    $badbots++;
                    
                    //block any bot with a score over 25 outright
                    if ($score >= 25) {
                        echo "Blocking {$ip}\n";
                        fwrite($banned_ips, $ip ."\n");
                        if (ENV == "PROD") {
                            shell_exec("/sbin/iptables -I INPUT -s {$ip} -j DROP");
                        }
                    }
                } elseif ($json->data->totalReports > 0) {
                    //evaluate reports
                    $lastReported = strtotime($json->data->lastReportedAt);
                    
                    if (($currentTime - $lastReported) < 2592000) {
                        //if the IP address has been reported within 30 days (2592000 seconds)
                        $badbots++;
                        $flaggedbots++;
                        echo "IP address {$ip} reported within 30 days.\n";
                    } else {
                        echo "Flagging {$ip}\n";
                        $flaggedbots++;
                    }
                }
                
                //if $badbots has reached 3, or at least 33% of the prefix cluster, block the prefix
                if ($badbots == 3) {
                    echo "Blocking {$notation}\n";
                    fwrite($banned_ips, $notation ."\n");
                    if (ENV == "PROD") {
                        shell_exec("/sbin/iptables -I INPUT -s {$notation} -j DROP");
                    }
                    //break the while loop at 3 to prevent further unnecessary API calls
                    break;
                }
            }
            $index++;
        }
        
        //if $badbots has not attained a 33% threshold
        if ($badbots < 3) {       
            if ($flaggedbots >= 7) {
                echo "Blocking {$notation}; too many flagged bots\n";
                fwrite($banned_ips, $notation ."\n");
                if (ENV == "PROD") {
                    shell_exec("/sbin/iptables -I INPUT -s {$notation} -j DROP");
                }
            } elseif ($flaggedbots >= 3  && $flaggedbots < 7) {
                echo "Flagging {$notation}\n";
                fwrite($flagged_ips, $notation ."\n");
                
                //also add to watchlist
                fwrite($watchlist, $notation ."\n");
                
                //read the watchlist and determine whether the notation has reached the WATCHLIST_BAN limit
                $watchlist_count = 0;
                while (($line = fgets($watchlist, 4096)) !== false) {
                    $line = trim($line);
                    
                    if ($line == $notation) {
                        $watchlist_count++;
                    }
                }
                
                if ($watchlist_count >= WATCHLIST_BAN) {
                    echo "Blocking watchlisted {$notation}\n";
                    fwrite($banned_ips, $notation ."\n");
                    if (ENV == "PROD") {
                        shell_exec("/sbin/iptables -I INPUT -s {$notation} -j DROP");
                    }
                }                
                
            } else {
                echo "Allowing {$notation}\n";
                fwrite($allowed_ips, $notation ."\n");
            }
        }
    } else {
        echo "Processed {$notation} already.\n";
    }
}

/***** PROCESS SUPERUSER IP ADDRESSES *****/
function process_superusers ($ips, $allowed_ips, $flagged_ips, $banned_ips, $processed_ips) {
    // $max / 2000 is the top 0.05% in number of HTTP requests, which casts a wide net for a large log file
    
    $max = count($ips);
    $gateway = $max / 2000;
    
    foreach ($ips as $ip=>$count) {        
        if ($count > $gateway && $count >= 100) {
            //ignore processing IP addresses of superusers if they have already been evaluated previously
            if (!in_array($ip, $processed_ips)) {
                evaluate_superuser($ip, $count, $allowed_ips, $flagged_ips, $banned_ips);
            } else {
                echo "Processed {$ip} already.\n";
            }
        }
    }    
}

//function for looking up the IP addresses that meet a minimum threshold for high usage in the Abuse IPDB API
function evaluate_superuser ($ip, $count, $allowed_ips, $flagged_ips, $banned_ips) {    
    
    //get JSON from Abuse IPDB API
    $json = lookup_ip($ip);
    
    if (isset($json->data->abuseConfidenceScore)) {
        $score = $json->data->abuseConfidenceScore;
        
        if ( $score >= 25) {
            echo "Banning {$ip} (score {$score})\n";
            fwrite($banned_ips, $ip ."\n");
            if (ENV == "PROD") {
                shell_exec("/sbin/iptables -I INPUT -s {$ip} -j DROP");
            }
        } elseif ($score < 25 && $score > 0) {
            echo "Flagging {$ip}\n";
            fwrite($flagged_ips, $ip ."\n");
        } else {
            //adding to daily whitelist
            fwrite($allowed_ips, $ip ."\n");
        }
    }
}

function lookup_ip ($ip) {
    //query IP address against Abuse IPDB API
    $url = "https://api.abuseipdb.com/api/v2/check?ipAddress={$ip}&maxAgeInDays=90";
    
    $headers = [
        'Accept: application/json',
        'Key: ' . API_KEY
    ];
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    
    $result = curl_exec($ch);
    $json = json_decode($result);
    curl_close($ch);
    
    return $json;    
}

//email daily report
function email_report($dateAgo) {
    $subject = "Baxter report for {$dateAgo}";
    
    $flagged_ips = fopen("flagged_ips", "r") or die("Unable to create or open flagged_ips");
    $banned_ips = fopen("banned_ips", "r") or die("Unable to create or open banned_ips");
    
    $flagged = array();
    while (($line = fgets($flagged_ips, 4096)) !== false) {
        $flagged[] = trim($line);
    }
    $banned = array();
    while (($line = fgets($banned_ips, 4096)) !== false) {
        $banned[] = trim($line);
    }
    
    fclose($flagged_ips);
    fclose($banned_ips);
    
    //only prepare the body and send the report if IP addressed or ranges have been flagged or banned from the server
    if (count($flagged) > 0 || count($banned) > 0) {
        $body = "Daily Baxter report for {$dateAgo}\n";
        
        if (count($flagged) > 0) {
            $body .= "\nFlagged IP addresses and ranges:\n";
            foreach ($banned as $line) {
                $body .= "{$line}\n";
            }
        }
        if (count($banned) > 0) {
            $body .= "\nBanned IP addresses and ranges:\n";
            foreach ($banned as $line) {
                $body .= "{$line}\n";
            }
        }
        
        echo "Emailing daily report.\n";
        mail(EMAIL, $subject, $body);
    }    
}

/***** VALIDATE CONFIG YAML FILE *****/
function validate_config () {
    $valid = true;
    
    if (defined('API_KEY')) {
        //lookup an ip
        $json = lookup_ip('8.8.8.8');
      
        if (!isset($json->data->abuseConfidenceScore)) {
          echo "API_KEY invalid or reached limit.\n";
          $valid = false;
        }
    } else {
        echo "API_KEY undefined.\n";
        $valid = false;
    }    
   
    if (defined('ENV')) {
        if (ENV != 'DEV' && ENV != 'PROD') {
            echo "ENV value is not DEV or PROD.\n";
            $valid = false;
        }
    } else {
        echo "ENV undefined.\n";
        $valid = false;
    }
    
    if (defined('INTERVAL')) {
        if (is_integer(INTERVAL)) {
            if (INTERVAL < 180) {
                echo "3 minute interval is likely too short to conclude.\n";
                $valid = false;
            }
        } else {
            echo "INTERVAL must be an integer.\n";
            $valid = false;
        }
    } else {
        echo "INTERVAL undefined.\n";
        $valid = false;
    }
    
    if (defined('CLUSTER_MINIMUM')) {
        if (!is_integer(CLUSTER_MINIMUM)) {
            echo "CLUSTER_MINIMUM is not an integer\n";
            $valid = false;
        }
    } else {
        echo "CLUSTER_MINIMUM undefined.\n";
        $valid = false;
    }
    
    if (defined('WATCHLIST_BAN')) {
        if (!is_integer(WATCHLIST_BAN)) {
            echo "WATCHLIST_BAN is not an integer\n";
            $valid = false;
        }
    } else {
        echo "WATCHLIST_BAN undefined.\n";
        $valid = false;        
    }
    
    if (defined('LOGFILE')) {
        $files = glob(LOGFILE);
        if (count($files) == 0) {
            echo "No files match LOGFILE path.\n";
            $valid = false;
        }
    } else {
        echo "LOGFILE path undefined.\n";
        $valid = false;
    }
    
    return $valid;
}

?>