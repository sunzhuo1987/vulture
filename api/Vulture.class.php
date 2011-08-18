<?php
class Vulture {
	protected $port;
	protected $vulture_ip;
	protected $proxy;
	protected static $socket;
	
	public function setIP($ip){
		$this->vulture_ip = $ip;	
	}

	public function setProxy($proxy){
		$this->proxy = $proxy;	
	}

	public function setIPbyHostName($hostname){
		$this->vulture_ip = gethostbyname($hostname);	
	}

	public function setPort($port){
		$this->port = $port;
	}

	//Check if user is logged at SSO Portal
	public function is_logged($login){
		if(!isset($this->vulture_ip) or !isset($login))
			throw new Exception ("Unable to get Vulture IP or Login @Vulture.class.php method : is_logged(API PHP) ");

		if(!isset($this->port))
			$this->port = 80;
			
		// Create a stream
		$opts = array(
		  'http'=>array(
		    'method'=>"GET",
		    'header'=>"Bot: API PHP"
		  )
		);
		if(isset($this->proxy))
			$opts['http']['proxy'] = $this->proxy;

		$context = stream_context_create($opts);		

		//Sending query and retrieve XML file
		$result = file_get_contents('http://'.$this->vulture_ip.':'.$this->port.'/saml/?'.http_build_query(array('action' => 'is_logged', 'login' => $login)), false, $context);

		$obj = simplexml_load_string($result);

		//Return is_logged value
		$res = (string)$obj->is_logged; 

		return $res == "true" ? true : false;
	}

	//Check if user is logged in app provided
	public function is_logged_app($app_name, $login){
		if(!isset($this->vulture_ip) or !isset($login) or !isset($app_name))
			throw new Exception ("Unable to get Vulture IP or Login or App name @Vulture.class.php method : is_logged_app(API PHP) ");

		if(!isset($this->port))
			$this->port = 80;
			
		// Create a stream
		$opts = array(
		  'http'=>array(
		    'method'=>"GET",
		    'header'=>"Bot: API PHP"
		  )
		);
		if(isset($this->proxy))
			$opts['http']['proxy'] = $this->proxy;

		$context = stream_context_create($opts);		

		//Sending query and retrieve XML file
		$result = file_get_contents('http://'.$this->vulture_ip.':'.$this->port.'/saml/?'.http_build_query(array('action' => 'is_logged_app', 'app_name' => $app_name, 'login' => $login)), false, $context);

		$obj = simplexml_load_string($result);

		//Return is_logged value
		$res = (string)$obj->is_logged; 

		return $res == "true" ? true : false;
	}

	//Logout user from SSO portal ONLY !
	//Can't disconnect user from app after this call 
	public function logout($login){
		if(!isset($this->vulture_ip) or !isset($login))
			throw new Exception ("Unable to get Vulture IP or Login @Vulture.class.php method : logout(API PHP) ");

		if(!isset($this->port))
			$this->port = 80;
			
		// Create a stream
		$opts = array(
		  'http'=>array(
		    'method'=>"GET",
		    'header'=>"Bot: API PHP"
		  )
		);
		if(isset($this->proxy))
			$opts['http']['proxy'] = $this->proxy;

		$context = stream_context_create($opts);		

		//Sending query and retrieve XML file
		file_get_contents('http://'.$this->vulture_ip.':'.$this->port.'/saml/?'.http_build_query(array('action' => 'logout', 'login' => $login)), false, $context);
	}

	//Logout user from app provided
	public function logout_app($app_name, $login){
		if(!isset($this->vulture_ip) or !isset($login) or !isset($app_name))
			throw new Exception ("Unable to get Vulture IP or Login @Vulture.class.php method : logout_app(API PHP) ");

		if(!isset($this->port))
			$this->port = 80;
			
		// Create a stream
		$opts = array(
		  'http'=>array(
		    'method'=>"GET",
		    'header'=>"Bot: API PHP"
		  )
		);
		if(isset($this->proxy))
			$opts['http']['proxy'] = $this->proxy;

		$context = stream_context_create($opts);		

		//Sending query and retrieve XML file
		file_get_contents('http://'.$this->vulture_ip.':'.$this->port.'/saml/?'.http_build_query(array('action' => 'logout_app', 'app_name' => $app_name, 'login' => $login)), false, $context);
	}
}
?>
