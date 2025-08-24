#import session
from urllib.parse import urlparse
import re
import whois
import datetime


#url input and parsing through urlparse
url=input("Enter the URL: ")
parsed=urlparse(url)

#var declaration through inbuilt functions
netloc=parsed.netloc
scheme=parsed.scheme
path=parsed.path
query=parsed.query
fragment=parsed.fragment
length=len(url)

#performance starts here
malicious=False
score=0
reasons=[]

#link checker starts checking here
if scheme=="http":
    malicious=True
    score+=5
    reasons.append("HTTP is a older version protocol iit may not be secure")
if len(path)>=100:
    malicious=True
    score+=10
    reasons.append("URL path length is too long")
if length>200:
    malicious=True
    score+=10
    reasons.append("URL is too long")


suspicious_tld=['tk','buzz','xyz','top','ga','ml','info','cf','gq','icu','wang','live','cn','online','host','ru']
brands=[ "google",
    "facebook",
    "amazon",
    "paypal",
    "apple",
    "microsoft",
    "instagram",
    "twitter",
    "linkedin",
    "netflix",
    "whatsapp",
    "telegram"]

val=1

if any(netloc.endswith("."+tld) for tld in suspicious_tld):
    malicious=True
    score+=25
    val=0
    reasons.append("URL domain name is malicious")
else:
    try:
        w = whois.whois(netloc)

        # Handle creation and expiration dates
        creation_date = w.creation_date
        expiration_date = w.expiration_date

        # Some WHOIS fields return lists
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        now = datetime.datetime.now()

        # Check expired domain
        if expiration_date and expiration_date < now:
            malicious = True
            score += 20
            reasons.append("Domain is expired")

        # Check if created within last 30 days
        if creation_date and (now - creation_date).days <= 30:
            malicious = True
            score += 10
            reasons.append("Domain created within last 30 days")

    except Exception as e:
        error_message = str(e)

        # Clean up WHOIS failure message
        if "No match for" in error_message:
            reasons.append("WHOIS lookup failed: Domain not found")
        elif "connection timed out" in error_message.lower():
            reasons.append("WHOIS lookup failed: Connection timed out")
        elif "quota" in error_message.lower():
            reasons.append("WHOIS lookup failed: Rate limit exceeded")
        else:
            reasons.append("WHOIS lookup failed: Data unavailable")

if "@" in netloc:
    malicious=True
    score+=10
    reasons.append("URL domain name includes @")
if netloc.count('-')>1:
    malicious=True
    score+=5
    reasons.append("URL domain name includes more hyphens ")
if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', netloc.split(':')[0]):
    malicious = True
    score += 25
    reasons.append("Domain is an IP address")
if netloc.count('.')>=3:
    malicious=True
    score+=5
    reasons.append("URL domain name includes more dots ")



replacement_map = {
    'a': ['@', '4'],
    'o': ['0'],
    'e': ['3'],
    'i': ['1', '|'],
    'l': ['1', '|'],
    's': ['5', '$'],
    'g': ['9'],
    't': ['7']
}

def is_misspelled_brand(domain, brands, replacement_map):
    for brand in brands:
        for i, char in enumerate(brand):
            if char in replacement_map:
                for replacement in replacement_map[char]:
                    fake_brand = brand[:i] + replacement + brand[i+1:]
                    if fake_brand in domain:
                        return True
    return False

if val == 1:
    if is_misspelled_brand(netloc, brands, replacement_map):
        malicious = True
        score += 20
        reasons.append("URL domain name is not legitimate check domain carefully words are misspelled")


if score >= 30:
    print("⚠️ High Risk: Likely Malicious")
    print("Malicious reasons", reasons)
    print("Malicious score", score)
elif 10 <= score < 30:
    print("⚠️ Medium Risk: Suspicious")
    print("Malicious reasons", reasons)
    print("Malicious score", score)
else:
    print("✅ Low Risk: Likely Safe")
    print("Malicious score", score)
