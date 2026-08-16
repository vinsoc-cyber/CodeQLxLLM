<?php
// CWE-1025: loose comparison vs user input — type juggling bypass
$expected_token = "abc123";
if ($expected_token == $_POST["token"]) {
    echo "Authenticated";
}
