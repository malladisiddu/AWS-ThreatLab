import json

def generate_report(scenario, detected, events):
    report = {
        'scenario': scenario,
        'detected': detected,
        'event_count': len(events),
        'events': events
    }
    with open(f"report_{scenario}.json", 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Report written to report_{scenario}.json")
