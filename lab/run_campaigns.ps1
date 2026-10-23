Set-Location $PSScriptRoot
$stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"=== E2 campaign start $stamp ===" | Out-File -Append -Encoding utf8 results\n8n_campaigns.log
python controller.py --arm n8n --scenario e2 --n 10 --spacing 300 --spacing-jitter 60 --seed 12345 *>> results\n8n_campaigns.log
$stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"=== E2 done, E3 start $stamp ===" | Out-File -Append -Encoding utf8 results\n8n_campaigns.log
python controller.py --arm n8n --scenario e3 --n 10 --spacing 300 --spacing-jitter 60 --seed 12345 *>> results\n8n_campaigns.log
$stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"=== ALL campaigns done $stamp ===" | Out-File -Append -Encoding utf8 results\n8n_campaigns.log
