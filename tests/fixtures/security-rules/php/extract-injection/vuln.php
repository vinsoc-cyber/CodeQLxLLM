<?php
// CWE-1062: extract() from $_GET — attacker controls all local vars
extract($_GET);
echo "Logged in as " . $user;
