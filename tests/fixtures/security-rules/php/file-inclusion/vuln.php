<?php
// CWE-98: user-controlled include path → LFI/RFI
$page = $_GET["page"];
include($page);
