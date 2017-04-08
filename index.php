<?
header('Content-type: text/html; charset=utf-8');


$fl = fopen("config.txt", "r");

$conf = array();
$l=0;
$strs = array("directory:","host:","user:",'password:','db_name:');
while (!feof($fl))
{
    $conf[$l]=fgets($fl);
    $conf[$l] = trim(str_replace($strs, '', $conf[$l]));
    $l++;
}





function setfl($conf,$ava,$tmp)
{
    @mkdir($conf[0],0777);
$ava = $_FILES['avatar'];
$tmp = $ava['tmp_name'];
    $info=getimagesize($tmp);
    if (preg_match('{image/(.*)}is',$info['mime'])) {
        $info = pathinfo($ava['name']);
        $filename = basename($ava['name'],'.'.$info['extension']);
        $filename= $filename . rand(0,9) . rand(0,9) . '.' . $info['extension'];
        $name = iconv(mb_detect_encoding(basename($ava['name'])),'windows-1251',"$conf[0]/" . $filename);
        move_uploaded_file($tmp, $name);
        $name=iconv('windows-1251', 'utf-8', $name);
        
        return $name;
    }
    else {die ('Попытка вставки неизображения');}
}


try {
    $pd = new PDO("mysql:host=$conf[1];dbname=$conf[4];charset=UTF8", $conf[2],$conf[3]);
} catch (PDOException $e) {
    die('Подключение не удалось: ' . $e->getMessage());
}

function tsk($n,$nam)
{
    if (!empty($_POST["$n"])) {
        $p = $_POST["$n"];
        
    } else {
        die('Пустое поле: '. $nam);
    }
    return $p;
}

function tskpt ($ar1, $ar2, $n)
{
    $ar1[0]=0;
    for ($i=1;$i<$n;$i++)
    {
        if (!preg_match($ar2[$i-1], $ar1[$i])) {
            die("Некорректный ввод поля №$key");
        }
    }
}



function protect()
{
	$n = func_num_args(); 
	$ms = func_get_args(); 
	$ms2=array();
	$ms2[0]=0;
	$j=1;

	for($i = 0; $i < $n; $i+=2)
	{
			

		if 	((preg_match('/(and|null|not|union|select|from|where|group|order|having|limit|into|file|case)/i', $ms[$i]) ) or (preg_match('/#=*/',$ms[$i])))
		{
            session_start();
			$_SESSION['time']=time();
			$_SESSION['time-del']=1;

			die ("Попытка SQL-атаки. Доступ закрыт на 3 минуты");
		}
		if 	(preg_match('(\<(/?[^>]+)>)', $ms[$i]))
		{
            session_start();
			$_SESSION['time']=time();
			$_SESSION['time-del']=2;
			die ("Попытка HTML-атаки. Доступ закрыт на 5 минут");
		}

		
	   	if (strpos($ms[$i+1], 'sql') !== false)
	   	{
	   		$ms[$i]=mysql_real_escape_string(stripslashes($ms[$i])); 
	   	}
	   	if (strpos($ms[$i+1], 'html') !== false)
	   	{
	   		$ms[$i]=htmlentities($ms[$i], ENT_IGNORE);
	   		$ms[$i] = htmlspecialchars($ms[$i], ENT_IGNORE);
	   		
	   	}
	   	$ms2[$j]=$ms[$i];
	   	$j++;
   } 
   return $ms2;
}


$m = array();
$m[0]=0;


if (isset($_POST['sub2'])) {
    
    $m = protect (
         tsk('log','логин' ), 'sqlhtml',
        tsk('pas','пароль' ), 'sqlhtml'
        
        );
     tskpt($m, array(
     "/((?=^.{8,}$)(?=.*[A-Za-z])(?!.*\W)((?:.*[0-9]){2,}).*)/u" ,
     "((?=^.{7,18}$)(?=.*[A-Z])(?!.*[А-Яа-яЁё])((?:.*[!@#$%^&*\[\]\{\}]){2,}).*)"
     
      ), 3);
     $m[2]=md5(md5($m[2]));

    $res = $pd->prepare("SELECT count(`log`) FROM  `user` where `log`=? and `pas`=?;");
    $res->execute(array($m[1],$m[2]));
    $resu = $res->fetchColumn(0);
    if ($resu > 0) 
    {
        $rs = $pd->prepare("SELECT * FROM  `user` where `log`=? and `pas`=?;");
        $rs->execute(array($m[1],$m[2]));

        $buf = $rs->fetch(PDO::FETCH_BOTH);
        session_start();
        $_SESSION['id']=$buf[0];   
        for ($i=3;$i<11;$i++)
        {
         $m[$i]=$buf[$i];
        }
        $_SESSION['id'] = $m[1];
    	$_SESSION['time'] = 1;
    	$_SESSION['time-del'] = 0;    
        require_once("room.html");
    } 
    else 
    {
        die("Неверный вввод логина или пароля");
    }
}
else
if ((isset($_POST['sub1']))||(isset($_POST['sub3']))) {

    session_start();
    $_SESSION['id'] = 0;

	 $m = protect (
	 	 tsk('log','логин' ), 'sqlhtml',
        tsk('pas','пароль' ), 'sqlhtml',
	 	tsk('name','имя' ), 'sqlhtml',
        tsk('surname','фамилия' ), 'sqlhtml',
        tsk('patron','отчество' ), 'sqlhtml',
        tsk('date','дата рождения' ), 'sqlhtml',
        tsk('email','email' ), 'sqlhtml',
        tsk('phone','телефон' ),  'sqlhtml'
        );
     tskpt($m, array(
     "/((?=^.{8,}$)(?=.*[A-Za-z])(?!.*\W)((?:.*[0-9]){2,}).*)/u" ,
     "((?=^.{7,18}$)(?=.*[A-Z])(?!.*[А-Яа-яЁё])((?:.*[!@#$%^&*\[\]\{\}]){2,}).*)",
     "/[0-9A-Za-zа-яА-ЯЁё]{2,14}/u",
     "/[A-Za-zа-яА-ЯЁё]{4,14}/u",
     "/[A-Za-zа-яА-ЯЁё]{4,14}/u",
     "/[0-9]+/u",
     "/[@]+/u",
     "/[0-9]+/u",
      ), 9);
     $m[2]=md5(md5($m[2]));

	if (isset($_POST['sub1'])) 
	{

        $res = $pd->prepare("SELECT count(`log`) FROM  `user` where `log`=?;");
    	$res->execute(array($m[1]));
    	$resu = $res->fetchColumn(0);
        if ($resu!=0) 
        {
        	die ('Данный логин существует');
        }
        $res = $pd->prepare("SELECT count(`email`) FROM  `user` where `email`=?;");
    	$res->execute(array($m[7]));
    	$resu = $res->fetchColumn(0);
        if ($resu!=0) 
        {
        	die ('Данный email существует');
        }  
        if (isset($_FILES['avatar'])) $ava = $_FILES['avatar'];
        if (isset($ava['tmp_name'])) $tmp = $ava['tmp_name'];
        if(is_uploaded_file($tmp)) $m[9] = setfl($conf,$ava,$tmp); else die ("Аватар не загружен ".$ava['error']);

    	  
    	$res = $pd->prepare("INSERT INTO `user` (`log`, `pas`, `name`, `surname`, `patron`, `date`, `email`, `phone`,`link`) VALUES (?,?,?,?,?,?,?,?,?);");
        $res->execute(array($m[1],$m[2],$m[3],$m[4],$m[5],$m[6],$m[7],$m[8],$m[9]));
        
    	$_SESSION['id'] = $m[1];
    	$_SESSION['time'] = 1;
    	$_SESSION['time-del'] = 0;
    	require_once("room.html");


        
    }

    if (isset($_POST['sub3'])) {

    	$res = $pd->prepare("SELECT count(`email`) FROM  `user` where `email`=? and not `log` = ?");
    	$res->execute(array($m[7],$m[1]));
    	$resu = $res->fetchColumn(0);
        if ($resu!=0) 
        {
        	die ('Данный email существует');
        } 
        $res = $pd->prepare("UPDATE `user` SET `name`= ?, `surname`=?, `patron`=? , `date`=?,`email`=? , `phone`=?   WHERE `log`=?;");
         $res->execute(array($m[3],$m[4],$m[5],$m[6],$m[7],$m[8],$m[1]));
        
         if(is_uploaded_file($tmp)) {$m[9]= setfl($conf,$ava,$tmp); 

            $res=$pd->prepare("UPDATE `user` SET `link`=? WHERE `log`=?;");
            $res->execute(array($m[9],$m[1]));
            
                }
           echo "Изменения приняты";
       }
   }
        

else
{
    session_start();
    if (isset($_SESSION['id']))
    {
    	if ((time()-$_SESSION['time']<300)&&($_SESSION['time-del']==2))
    	{
    		die ("Попытка HTML-атаки. Доступ закрыт на 5 минут");
    	}
    	if ((time()-$_SESSION['time']<180)&&($_SESSION['time-del']==1))
    	{
    		die ("Попытка SQL-атаки. Доступ закрыт на 3 минуты");
    	}

    	$res = $pd->prepare("SELECT count(`log`) FROM  `user` where log=?;");
        $res->execute(array($_SESSION['id']));
        $resu = $res->fetchColumn(0);
       
        if ($resu > 0) {
            $rs = $pd->prepare("SELECT * FROM  `user` where log=?;");
            $rs->execute(array($_SESSION['id']));
            
            $buf = $rs->fetch(PDO::FETCH_BOTH);
                 
            for ($i=1;$i<11;$i++)
            {
             $m[$i]=$buf[$i];
            }
            require_once("room.html");
        }
        else  require_once("registration.html");   
    	
    }
    else
    {

    	require_once("registration.html");
        
    }
}

$pd = null;



