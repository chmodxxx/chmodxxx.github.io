---
layout: post
title: Insomni'Hack teaser 2019 l33thoster writeup
---

# Description
You can host your l33t pictures here.

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

The challenge is basically asking for a `.htaccess` upload while bypassing all restrictions, we need a valid image header that will not break `.htaccess` syntax, which is `wbmp` , we craft our `.htaccess` file and add a directive to make our custom extension files be interpreted as `PHP`.
![screen1.png]({{ site.url }}/assets/2019-01-21-Insomni'Hack-l33thoster-Writeup/screen1.png)
We do the same thing to upload our php file with the custom extension the content isn't important.
![screen2.png]({{ site.url }}/assets/2019-01-21-Insomni'Hack-l33thoster-Writeup/screen1.png)

The next step is to edit `.htaccess` file and add two more directives, the first one is disable php session upload_progress cleanup, and the second one is append file which will be a custom session one.

![screen3.png]({{ site.url }}/assets/2019-01-21-Insomni'Hack-l33thoster-Writeup/screen1.png)
Note that PHP_SESSION_UPLOAD_PROGRESS will create a session file for me, and disabling the cleanup will not remove my files so I don't need to do any kind of race conditions.

```sh
curl -vvv http://35.246.234.136/images/cce36633671a3a556973a0b2d3592fe4371a5bde/test.xyz -H 'Cookie: PHPSESSID=xyz' -F "PHP_SESSION_UPLOAD_PROGRESS=whatever" -F "file=@/etc/passwd"
```