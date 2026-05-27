#!/bin/bash
cd "$(dirname "$0")"
python3 check_urls.py --input urls.txt --output results.csv --flagged-output flagged.csv --api-key API_KEY_HERE
