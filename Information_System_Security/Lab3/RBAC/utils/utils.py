

def permission_complete(permission):
    permission=str(permission)
    permission_len=len(permission)
    if permission_len<5:
        permission='0'*(5-permission_len)+permission
    return permission

