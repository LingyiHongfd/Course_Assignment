from utils.db_operation import *
from user.user_class import *




RBAC_STR='[RBAC] '


def login():
    input_name=str(input(RBAC_STR+'Login User Name: '))
    print(RBAC_STR+'Try Login As '+input_name)
    finding=user_check(input_name)
    if finding==True:
        name,id=user_name2id(input_name)
        return User(name,id)
    else:
        return None










