<?php
echo "test";
include ('Vulture.class.php');



$log = new Vulture();

$log->setIP("127.0.0.1");
$log->setPort("8181");

if($log->is_logged("admin"))
	echo "COOl";
else
	echo "PAS COOL";



if($log->logout("admin"))
	echo "DECO";
else
	echo "PAS DECO";


if($log->is_logged("admin"))
	echo "COOl";
else
	echo "PAS COOL";

?>

