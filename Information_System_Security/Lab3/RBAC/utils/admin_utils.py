import pandas as pd
import os
from utils.db_operation import *

RBAC_STR='[RBAC] '

ADMIN_CMD_LIST=['show_user','show_role','show_permission','modify_user','modify_role','modify_permission']


def command(command_str,):
    if command_str in ADMIN_CMD_LIST:
        if command_str=='show_user':
            user_show()
        if command_str=='show_role':
            role_show()
        if command_str=='show_permission':
            permission_show()
        if command_str=='modify_user':
            user_modify()
        if command_str=='modify_role':
            role_modify()
        if command_str=='modify_permission':
            permission_modify()




