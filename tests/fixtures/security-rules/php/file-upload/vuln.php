<?php
$target = '/var/www/uploads/' . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $target);
