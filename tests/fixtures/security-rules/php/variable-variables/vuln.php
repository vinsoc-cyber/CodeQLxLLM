<?php
// CWE-621: variable-variable assignment from user input
$name = $_GET["name"];
$$name = $_GET["value"];
