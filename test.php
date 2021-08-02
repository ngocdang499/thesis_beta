<?php
session_start();
if(!$_SESSION['USER_NAME']) {
 echo "Need to login";
}
else {
 $Host= '192.168.1.8';
 $Dbname= 'app';
 $User= 'yyy';
 $Password= 'xxx';
 $Schema = 'test';
 $Conection_string="host=$Host dbname=$Dbname user=$User password=$Password";
 $Connect=pg_connect($Conection_string,$PGSQL_CONNECT_FORCE_NEW);
 if($_SERVER['REQUEST_METHOD'] == "POST") {
  $query="update $Schema.members set display_name='".$_POST['disp_name']."' where user_name='".$_SESSION['USER_NAME']."';";
  pg_query($Connect,$query);
  echo "Update Success";
 }
 else {
  if(strcmp($_SESSION['USER_NAME'],'admin')==0) {
   echo "Welcome admin<br><hr>";
   echo "List of user's are<br>";
   $query = "select display_name from $Schema.members where user_name!='admin'";
   $res = pg_query($Connect,$query);
   while($row=pg_fetch_array($res,NULL,PGSQL_ASSOC)) {
    echo "$row[display_name]<br>";
   }
 }
 else {
  echo "<form name=\"tgs\" id=\"tgs\" method=\"post\" action=\"home.php\">";
  echo "Update display name:<input type=\"text\" id=\"disp_name\" name=\"disp_name\" value=\"\">";
  echo "<input type=\"submit\" value=\"Update\">";
 }
}
}
?>