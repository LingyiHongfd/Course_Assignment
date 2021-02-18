import pandas as pd
import os
from role.role_class import Role
from utils.utils import *


RBAC_STR='[RBAC] '

###########################################################
# data base operation for user
###########################################################

def user_check(name):
    user_csv_path=r'./database/user.csv'
    user_csv=pd.read_csv(user_csv_path)
    user_csv_len=len(user_csv)
    for i in range (user_csv_len):
        if user_csv['user_name'][i]==name:
            return True
    return False

def user_name2id(name):
    user_csv_path=r'./database/user.csv'
    user_csv=pd.read_csv(user_csv_path)
    user_csv_len=len(user_csv)
    for i in range (user_csv_len):
        if user_csv['user_name'][i]==name:
            return  user_csv['user_name'][i],user_csv['user_id'][i]


def user_id2role_list(id):
    user2role_csv_path=r'./database/user2role.csv'
    user2role_csv=pd.read_csv(user2role_csv_path)
    user2role_csv_len=len(user2role_csv)
    role_list=[]
    for i in range (user2role_csv_len):
        if user2role_csv['user_id'][i]==id:
            role_list.append(role_id2role(user2role_csv['role_id'][i]))
    return role_list

def role_id2role(id):
    role_csv_path=r'./database/role.csv'
    role_csv=pd.read_csv(role_csv_path)
    role_csv_len=len(role_csv)
    for i in range (role_csv_len):
        if role_csv['role_id'][i]==id:
            role_id=role_csv['role_id'][i]
            role_name=role_csv['role_name'][i]
            role_rank=role_csv['rank'][i]
            role_exclusion=role_csv['exclusion'][i]
            role_permission=role_id2permission_id(role_id)

    new_role=Role(role_id,role_name,role_rank,role_exclusion,role_permission)
    return new_role

def role_id2permission_id(id):
    role2permission_csv_path=r'./database/role2permission.csv'
    role2permission_csv=pd.read_csv(role2permission_csv_path)
    role2permission_csv_len=len(role2permission_csv)
    for i in range (role2permission_csv_len):
        if role2permission_csv['role_id'][i]==id:
            permission=permission_id2permission(role2permission_csv['permission_id'][i])
            return permission



def permission_id2permission(id):
    permission_csv_path=r'./database/permission.csv'
    permission_csv=pd.read_csv(permission_csv_path)
    permission_csv_len=len(permission_csv)
    for i in range (permission_csv_len):
        if permission_csv['permission_id'][i]==id:
            permission=str(permission_csv['permission_label'][i])
            return permission_complete(permission)



#########################################################################
# database operation for admin
#########################################################################




def user_show():
    print (RBAC_STR+'User Show.')
    user_csv_path=r'./database/user.csv'
    user_csv=pd.read_csv(user_csv_path)
    print (user_csv)


def role_show():
    print (RBAC_STR+'Role Show.')
    role_csv_path=r'./database/role.csv'
    role_csv=pd.read_csv(role_csv_path)
    print (role_csv)




def permission_show():
    print (RBAC_STR+'Permission Show.')
    permission_csv_path=r'./database/permission.csv'
    permission_csv=pd.read_csv(permission_csv_path)
    print (permission_csv)

def user_modify():
    print (RBAC_STR+'User Modify.')
    cur_user_name=input(RBAC_STR+'Please Input Current User Name: ')
    new_user_name=input(RBAC_STR+'Please Input New User Name: ')
    user_csv_path=r'./database/user.csv'
    user_csv=pd.read_csv(user_csv_path)
    user_csv_len=len(user_csv)
    for i in range (user_csv_len):
        if user_csv['user_name'][i]==cur_user_name:
            user_csv['user_name'][i]=new_user_name
    os.remove(user_csv_path)
    user_csv.to_csv (user_csv_path, index = None, header=True) 
    print (RBAC_STR+'User Modify Successfully.')
    

def role_modify():
    print (RBAC_STR+'Role Modify.')
    cur_role_name=input(RBAC_STR+'Please Input Current Role Name: ')
    new_role_name=input(RBAC_STR+'Please Input New Role Name: ')
    new_role_rank=input(RBAC_STR+'Please Input New Role Rank: ')
    new_role_exclusion=input(RBAC_STR+'Please Input New Role Exclusion: ')
    role_csv_path=r'./database/role.csv'
    role_csv=pd.read_csv(role_csv_path)
    role_csv_len=len(role_csv)
    for i in range (role_csv_len):
        if role_csv['role_name'][i]==cur_role_name:
            role_csv['role_name'][i]=new_role_name
            role_csv['rank'][i]=new_role_rank
            role_csv['exclusion'][i]=new_role_exclusion
    os.remove(role_csv_path)        
    role_csv.to_csv (role_csv_path, index = None, header=True) 
    print (RBAC_STR+'Role Modify Successfully.')


def permission_modify():
    print (RBAC_STR+'Permission Modify.')
    cur_permission_id=int(input(RBAC_STR+'Please Input Current Permission ID: '))
    new_permission_label=str(input(RBAC_STR+'Please Input New Permission Label: '))
    permission_csv_path=r'./database/permission.csv'
    permission_csv=pd.read_csv(permission_csv_path)
    permission_csv_len=len(permission_csv)
    for i in range (permission_csv_len):
        if permission_csv['permission_id'][i]==cur_permission_id:
            permission_csv['permission_label'][i]=new_permission_label
    os.remove(permission_csv_path)
    permission_csv.to_csv (permission_csv_path, index = None, header=True) 
    print (RBAC_STR+'Permission Modify Successfully.')







