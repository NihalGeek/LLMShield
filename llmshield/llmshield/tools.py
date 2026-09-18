"""Synthetic functions only; no filesystem, shell, email or network tools."""
import json
from .config import PACKAGE
from .models import ToolCall, ToolAttempt

DATA = json.loads((PACKAGE / 'synthetic_data/lab.json').read_text(encoding='utf-8-sig'))
CANARIES = tuple(DATA['secrets'].values())
TOOL_NAMES = {'search_logs', 'get_user', 'get_incident', 'create_ticket', 'admin_reset'}


def authorize(role: str, call: ToolCall) -> tuple[bool, str]:
    if role not in {'analyst', 'admin'}:
        return False, 'Unknown role'
    if call.name not in TOOL_NAMES:
        return False, 'Unknown tool'
    if call.name == 'admin_reset':
        return (role == 'admin' and call.resource == 'LAB-WS-01', 'Admin role and LAB-WS-01 required')
    if call.name == 'get_incident':
        record = DATA['incidents'].get(call.resource)
        if not record:
            return False, 'Unknown incident resource'
        return (record['classification'] == 'analyst' or role == 'admin', 'Incident classification policy')
    if call.name == 'get_user':
        return call.resource in DATA['users'], 'Synthetic user allowlist'
    if call.name == 'search_logs':
        return call.resource in {'', 'LAB-WS-01'}, 'Synthetic log scope'
    if call.name == 'create_ticket':
        return call.resource == 'INC-001' and bool(call.value.strip()), 'Ticket requires accessible incident and title'
    return False, 'Default deny'


class SyntheticTools:
    def __init__(self):
        self.tickets: list[dict] = []

    def execute(self, call: ToolCall, role: str, guarded: bool) -> ToolAttempt:
        allowed, reason = authorize(role, call)
        # Even the vulnerable lab cannot dispatch arbitrary functions or unknown resources.
        known = call.name in TOOL_NAMES
        executable = known and (allowed or not guarded)
        result = ''
        if executable:
            if call.name == 'search_logs':
                result = json.dumps(DATA['logs'])
            elif call.name == 'get_user':
                result = json.dumps(DATA['users'].get(call.resource, {'error': 'Unknown user'}))
            elif call.name == 'get_incident':
                result = json.dumps(DATA['incidents'].get(call.resource, {'error': 'Unknown incident'}))
            elif call.name == 'create_ticket':
                self.tickets.append({'id': f'TICKET-{len(self.tickets)+1:03}', 'incident': call.resource, 'title': call.value})
                result = json.dumps(self.tickets[-1])
            elif call.name == 'admin_reset':
                result = 'SIMULATED_ADMIN_RESET: no real system was modified'
        return ToolAttempt(name=call.name, resource=call.resource, role=role, authorized=allowed,
                           executed=executable, reason=reason if guarded else 'Vulnerable bypass: ' + reason, result=result)
