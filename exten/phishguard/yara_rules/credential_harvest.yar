rule External_Form_Post_Collector
{
    meta:
        description = "Detects forms posting credentials to external destinations"
        severity = "high"
    strings:
        $form = "<form" nocase ascii
        $post = "method=\"post\"" nocase ascii
        $action = "action=\"http" nocase ascii
        $password = "password" nocase ascii
        $email = "email" nocase ascii
        $username = "username" nocase ascii
    condition:
        $form and $post and $action and 1 of ($password, $email, $username)
}

rule JavaScript_Credential_Stealer
{
    meta:
        description = "Detects JavaScript patterns associated with credential stealing or exfiltration"
        severity = "high"
    strings:
        $xhr = "XMLHttpRequest" nocase ascii
        $fetch = "fetch(" nocase ascii
        $beacon = "navigator.sendBeacon" nocase ascii
        $formdata = "FormData(" nocase ascii
        $local = "localStorage" nocase ascii
        $session = "sessionStorage" nocase ascii
        $token = "/api/token" nocase ascii
    condition:
        3 of them
}

rule Encoded_Credential_Exfiltration
{
    meta:
        description = "Detects encoding and redirect patterns used to hide credential exfiltration"
        severity = "medium"
    strings:
        $btoa = "btoa(" nocase ascii
        $atob = "atob(" nocase ascii
        $base64 = "base64" nocase ascii
        $redirect = "window.location" nocase ascii
        $cookie = "document.cookie" nocase ascii
        $submit = ".submit()" nocase ascii
    condition:
        2 of them
}
