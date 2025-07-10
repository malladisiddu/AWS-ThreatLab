#!/usr/bin/Python3
#Author: Siddartha Malladi
#Twitter: st0ic3r
import json
from datetime import datetime
from decimal import Decimal

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Decimal):
            return float(obj)
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        elif hasattr(obj, 'isoformat'):
            return obj.isoformat()
        try:
            return str(obj)
        except:
            return f"<{type(obj).__name__}: not serializable>"

def generate_report(scenario, detected, events):
    timestamp = datetime.utcnow().isoformat()
    
    report = {
        'scenario': scenario,
        'detected': detected,
        'event_count': len(events),
        'timestamp': timestamp,
        'events': events
    }

    filename = f"report_{scenario}.json"
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, cls=CustomJSONEncoder, default=str)
        print(f"Report written to {filename}")
    except Exception as e:
        print(f"Error writing report: {e}")
        simplified_report = {
            'scenario': scenario,
            'detected': detected,
            'event_count': len(events),
            'timestamp': timestamp,
            'error': f"Could not serialize events: {e}"
        }
        try:
            with open(filename, 'w') as f:
                json.dump(simplified_report, f, indent=2)
            print(f"Simplified report written to {filename}")
        except Exception as e2:
            print(f"Failed to write any report: {e2}")
