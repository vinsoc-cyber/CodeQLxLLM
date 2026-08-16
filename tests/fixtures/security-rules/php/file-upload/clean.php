<?php
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
$allowed = ['jpg', 'png'];
if (in_array($ext, $allowed, true)) {
    $name = bin2hex(random_bytes(16)) . '.' . $ext;
    move_uploaded_file($_FILES['file']['tmp_name'], '/var/www/uploads/' . $name);
}
