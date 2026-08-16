<?php
// Strict comparison — safe from type juggling
$expected_token = "abc123";
if ($expected_token === $_POST["token"]) {
    echo "Authenticated";
}
