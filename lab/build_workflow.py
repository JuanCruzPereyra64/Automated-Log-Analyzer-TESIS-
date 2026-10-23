import json, sys, pathlib
sys.stdout.reconfigure(encoding='utf-8')

base = pathlib.Path(__file__).resolve().parent
code = (base / "pipeline.js").read_text(encoding="utf-8")

wf = {
    "id": "AZj9XoI9f4EiKcY1",
    "name": "SIEM_SOAR_Pipeline",
    "active": True,
    "nodes": [
        {
            "parameters": {
                "rule": {"interval": [{"field": "minutes", "minutesInterval": 1}]}
            },
            "name": "ScheduleTrigger",
            "type": "n8n-nodes-base.scheduleTrigger",
            "typeVersion": 1.2,
            "position": [-200, -100],
            "id": "sched-1"
        },
        {
            "parameters": {},
            "name": "ManualTrigger",
            "type": "n8n-nodes-base.manualTrigger",
            "typeVersion": 1,
            "position": [-200, 100],
            "id": "manual-1"
        },
        {
            "parameters": {
                "httpMethod": "POST",
                "path": "runpipeline",
                "responseMode": "lastNode",
                "options": {}
            },
            "name": "Webhook",
            "type": "n8n-nodes-base.webhook",
            "typeVersion": 2,
            "position": [-200, 300],
            "id": "wh-1",
            "webhookId": "runpipeline-wh-001"
        },
        {
            "parameters": {"jsCode": code},
            "name": "Pipeline",
            "type": "n8n-nodes-base.code",
            "typeVersion": 2,
            "position": [60, 100],
            "id": "code-1"
        }
    ],
    "connections": {
        "ScheduleTrigger": {"main": [[{"node": "Pipeline", "type": "main", "index": 0}]]},
        "ManualTrigger": {"main": [[{"node": "Pipeline", "type": "main", "index": 0}]]},
        "Webhook": {"main": [[{"node": "Pipeline", "type": "main", "index": 0}]]}
    },
    "settings": {"executionOrder": "v1", "saveManualExecutions": True, "saveExecutionProgress": True}
}

out = base / "pipeline-wf.json"
out.write_text(json.dumps(wf, ensure_ascii=False, indent=2), encoding="utf-8")
print("written", out)
