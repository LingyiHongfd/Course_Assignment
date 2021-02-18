from user.user_class import *
from role.role_class import *
from session.session import *


USER_CMD_LIST=['create_session','show_roles','show_session','get_session','add_role','visit']

RBAC_STR='[RBAC] '


def command(command_str,user,session):
    if command_str in USER_CMD_LIST:
        if command_str=='create_session':
            user.create_session()
            return user,session
        if command_str=='show_roles':
            user.show_roles()
            return user,session
        if command_str=='get_session':
            input_session_idx=input(RBAC_STR+'Session id: ')
            session=user.get_certain_session(int(input_session_idx))
            return user,session
        if command_str=='show_session':
            user.show_session()
            return user,session
        if command_str=='add_role':
            input_role_name=input(RBAC_STR+'Role Name: ')
            session.add_role(str(input_role_name))
            return user,session
        if command_str=='visit':
            input_visit=input(RBAC_STR+'Visit Action: ')
            session.visit(str(input_visit))
            return user,session
    return user,session






