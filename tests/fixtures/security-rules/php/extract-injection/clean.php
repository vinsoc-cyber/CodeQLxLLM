<?php
// EXTR_SKIP prevents overwriting existing variables
$is_admin = false;
extract($_GET, EXTR_SKIP);
if ($is_admin) {
    echo "Admin panel";
}
