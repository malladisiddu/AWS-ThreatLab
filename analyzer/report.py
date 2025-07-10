import json
from datetime import datetime
from decimal import Decimal

class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle datetime objects and other AWS types"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Decimal):
            return float(obj)
        elif hasattr(obj, '__dict__'):
            # Handle any object with attributes by converting to dict
            return obj.__dict__
        elif hasattr(obj, 'isoformat'):
            # Handle any date-like object
            return obj.isoformat()
        try:
            # Try to convert to string as fallback
            return str(obj)
        except:
            return f"<{type(obj).__name__}: not serializable>"

def generate_report(scenario, detected, events):
    """Generate a JSON report for the given scenario"""
    # Create timestamp for the report
    timestamp = datetime.utcnow().isoformat()
    
    report = {
        'scenario': scenario,
        'detected': detected,
        'event_count': len(events),
        'timestamp': timestamp,
        'events': events
    }
    
    # Write report with custom encoder
    filename = f"report_{scenario}.json"
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, cls=CustomJSONEncoder, default=str)
        print(f"Report written to {filename}")
    except Exception as e:
        print(f"Error writing report: {e}")
        # Try to write a simplified report without events
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
