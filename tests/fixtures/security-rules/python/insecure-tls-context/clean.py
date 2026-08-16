# Default-secure context — safe
import ssl

ctx = ssl.create_default_context()
# check_hostname and CERT_REQUIRED are the defaults — don't disable them
