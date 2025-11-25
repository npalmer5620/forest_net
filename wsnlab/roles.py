from enum import Enum

Roles = Enum('Roles', 'UNDISCOVERED UNREGISTERED ROOT REGISTERED CLUSTER_HEAD ROUTER')

def _role_name(r): return r.name if hasattr(r, "name") else str(r)

