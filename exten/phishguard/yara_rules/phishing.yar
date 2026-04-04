rule Phishing_Page_Structure_Common
{
    meta:
        description = "Matches common phishing page structure and login collection markers"
        severity = "high"
    strings:
        $form = "<form" nocase ascii
        $password = "type=\"password\"" nocase ascii
        $email = "type=\"email\"" nocase ascii
        $submit = "submit" nocase ascii
        $remember = "remember me" nocase ascii
        $signin = "sign in" nocase ascii
        $login = "/login" nocase ascii
    condition:
        3 of ($form, $password, $email, $submit, $remember, $signin, $login)
}

rule Brand_Impersonation_Login_Portal
{
    meta:
        description = "Detects brand impersonation patterns used by phishing portals"
        severity = "high"
    strings:
        $paypal = "paypal" nocase ascii
        $google = "google" nocase ascii
        $microsoft = "microsoft" nocase ascii
        $office = "office365" nocase ascii
        $amazon = "amazon" nocase ascii
        $verify = "verify your account" nocase ascii
        $confirm = "confirm your identity" nocase ascii
        $security = "security alert" nocase ascii
        $reauth = "reauthenticate" nocase ascii
    condition:
        1 of ($paypal, $google, $microsoft, $office, $amazon) and 1 of ($verify, $confirm, $security, $reauth)
}

rule Fake_Login_Page_Indicators
{
    meta:
        description = "Detects fake login page messaging and suspicious account prompts"
        severity = "medium"
    strings:
        $limited = "limited time" nocase ascii
        $suspended = "account suspended" nocase ascii
        $urgent = "act now" nocase ascii
        $confirm = "confirm account" nocase ascii
        $unlock = "unlock your account" nocase ascii
        $restore = "restore access" nocase ascii
        $verify = "verify immediately" nocase ascii
    condition:
        2 of them
}

rule Account_Verification_Pressure_Text
{
    meta:
        description = "Detects account-verification phishing language in plain-text emails and messages"
        severity = "medium"
    strings:
        $threat1 = "security alert" nocase ascii
        $threat2 = "unusual activity" nocase ascii
        $threat3 = "unauthorized access" nocase ascii
        $threat4 = "account suspended" nocase ascii
        $threat5 = "confirm your identity" nocase ascii
        $action1 = "verify your account" nocase ascii
        $action2 = "verify immediately" nocase ascii
        $action3 = "click here to login" nocase ascii
        $action4 = "log in to avoid" nocase ascii
        $action5 = "reset your password" nocase ascii
        $action6 = "restore access" nocase ascii
    condition:
        1 of ($threat*) and 1 of ($action*)
}

rule AI_Templated_Phishing_Language
{
    meta:
        description = "Detects polished, templated social-engineering language often seen in AI-generated phishing"
        severity = "medium"
    strings:
        $p1 = "dear customer" nocase ascii
        $p2 = "valued customer" nocase ascii
        $p3 = "this is an automated message" nocase ascii
        $p4 = "immediate action is required" nocase ascii
        $p5 = "failure to comply" nocase ascii
        $p6 = "click the secure link below" nocase ascii
        $p7 = "do not reply to this message" nocase ascii
        $p8 = "for your security" nocase ascii
        $p9 = "ensure continued access" nocase ascii
        $p10 = "your prompt attention" nocase ascii
        $p11 = "maintain uninterrupted access" nocase ascii
        $p12 = "as a precautionary measure" nocase ascii
    condition:
        3 of them
}

rule Obfuscated_Link_Lure_Text
{
    meta:
        description = "Detects text phishing that hides or obfuscates a destination URL while pressuring the user to act"
        severity = "high"
    strings:
        $obf1 = "hxxp://" nocase ascii
        $obf2 = "hxxps://" nocase ascii
        $obf3 = "[.]" nocase ascii
        $obf4 = "(.)" nocase ascii
        $lure1 = "click this link" nocase ascii
        $lure2 = "click the secure link below" nocase ascii
        $lure3 = "verify your account" nocase ascii
        $lure4 = "confirm your identity" nocase ascii
        $lure5 = "download apk" nocase ascii
        $lure6 = "login to continue" nocase ascii
    condition:
        1 of ($obf*) and 1 of ($lure*)
}

rule Chat_Scam_Collection_Patterns
{
    meta:
        description = "Detects OTP, payment, and WhatsApp social-engineering collection scripts in chat text"
        severity = "high"
    strings:
        $c1 = "share the otp" nocase ascii
        $c2 = "send me the code" nocase ascii
        $c3 = "urgent transfer" nocase ascii
        $c4 = "payment screenshot" nocase ascii
        $c5 = "verify your whatsapp" nocase ascii
        $c6 = "download apk" nocase ascii
        $c7 = "bank transfer" nocase ascii
        $c8 = "gift card" nocase ascii
        $c9 = "crypto" nocase ascii
        $c10 = "join this group" nocase ascii
        $c11 = "click this link" nocase ascii
    condition:
        2 of them
}
