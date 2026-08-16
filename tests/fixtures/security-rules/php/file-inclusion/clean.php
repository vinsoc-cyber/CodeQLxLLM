<?php
// Allowlist dispatch — safe
$allowed = ["home" => "home.php", "about" => "about.php"];
$page = $_GET["page"] ?? "home";
if (isset($allowed[$page])) {
    include($allowed[$page]);
}
