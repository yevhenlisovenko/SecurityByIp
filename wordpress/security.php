<?php
	
$key = 'fb781ed4afdab682fe21844827734584';	
	
if (isset($_GET['key']) && $_GET['key'] = $key){
	$ipArr = explode(".", $_SERVER['REMOTE_ADDR']);
	if (count($ipArr) == 4){
		$ipArr[3] = '*';
		$ip = implode(".", $ipArr);
		
		$myfile = fopen(realpath(dirname(__FILE__)).'/securityallowip.txt', "a") or die("error: Unable to open file!");
		fwrite($myfile, $ip."\n");
		fclose($myfile);
		die('successful ('.$ip.'): your ip address has added.');
			
	}else{
		die('error: your ip address is not valid.');
	}
}
	
function disableGuests() {
	
	$file = file_get_contents(realpath(dirname(__FILE__)).'/securityallowip.txt');
	$lines = (array)explode("\n", $file);
	
	$networks = array();
	foreach($lines as $ip){
		if (trim($ip) != ""){
			$networks[] = trim($ip);
		}
	}
	
    foreach($networks as $network) {

        $network = preg_replace('~\s~', '', $network);
        $ip = $_SERVER['REMOTE_ADDR'];
        if ($ip == $network)
            return true;

        if (strpos($network, '*') !== FALSE) {
            if (strpos($network, '/') !== FALSE) {
                $asParts = explode('/', $network);
                if (isset($asParts[0]))
	                $network = $asParts[0];
	            else
	                $network = '';
            }
            $nCount = substr_count($network, '*');
            $network = str_replace('*', '0', $network);
            if ($nCount == 1) {
                $network .= '/24';
            } else if ($nCount == 2) {
                $network .= '/16';
            } else if ($nCount == 3) {
                $network .= '/8';
            } else if ($nCount > 3) {
                return true;
            }
        }

        $d = strpos($network, '-');
        if ($d === FALSE) {
            $ip_arr = explode('/', $network);
            if (!preg_match("@\d*\.\d*\.\d*\.\d*@", $ip_arr[0], $matches)) {
                $ip_arr[0] .= ".0";
            }

            $network_long = ip2long($ip_arr[0]);
            $x = ip2long($ip_arr[1]);
            $mask = long2ip($x) == $ip_arr[1] ? $x : (0xffffffff << (32 - $ip_arr[1]));
            $ip_long = ip2long($ip);
            if (($ip_long & $mask) == ($network_long & $mask))
                return true;
        } else {
            $from = trim(ip2long(substr($network, 0, $d)));
            $to = trim(ip2long(substr($network, $d + 1)));
            $ip = ip2long($ip);
            if (($ip >= $from and $ip <= $to))
                return true;
        }
    }

    echo '<!-- access denied your ip: '.$_SERVER['REMOTE_ADDR'].' -->';
    header('HTTP/1.1 503 Service Temporarily Unavailable');
    header('Status: 503 Service Temporarily Unavailable');
    header('Retry-After: 3000');
    exit;
}
disableGuests();