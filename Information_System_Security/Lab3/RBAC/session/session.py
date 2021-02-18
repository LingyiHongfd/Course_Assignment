from utils.utils import *


RBAC_STR='[RBAC] '

ACTION_LIST=['n','r','e','d','w']

class Session(object):
    def __init__(self,name,pos_role_list):
        self.session_user_name=name
        self.role_list=[]
        self.permission='00000'
        self.role_list=[]
        self.role_list_len=len(self.role_list)
        self.pos_role_list=pos_role_list
        self.pos_role_list_len=len(self.pos_role_list)


    def get_permission(self):
        return str(self.permission)

    def check_exclusion(self,target_role):
        target_role_exclusion=target_role.get_exclussion()
        if target_role_exclusion == 0:
            return False
        for i in range (self.role_list_len):
            p_role_exclusion=self.role_list[i].get_exclusion()
            if p_role_exclusion !=0 and p_role_exclusion==target_role_exclusion:
                return True
        return False


    def check_exist(self,target_role):
        target_role_name=target_role.get_role_name()
        for i in range(self.role_list_len):
            if self.role_list[i].get_role_name()==target_role_name:
                return True
        return False


    def add_role(self,role_name):
        for i in range (self.pos_role_list_len):
            if self.pos_role_list[i].get_role_name()==role_name:
                target_role=self.pos_role_list[i]
                _existing=self.check_exist(target_role)
                if _existing == True:
                    print (RBAC_STR+'Add Role Failed: Role Has Been Added.')
                    return 
                _exclusion=self.check_exclusion(target_role)
                if _exclusion==True:
                    print (RBAC_STR+'Add Role Failed: Role Exclusion.')
                    return 
                else:
                    self.role_list.append(target_role)
                    self.role_list_len=len(self.role_list)
                    self.permission_update(target_role.get_permission())
                    print (RBAC_STR+'Add Role Succeed: Role '+role_name+' Added.')


    def visit(self,action):
        '''
        action:
        n create
        r read
        e execute
        d delete
        w write      
        '''
        action=str(action)
        if action in ACTION_LIST:
            self.check_permission(action)
        else:
            print (RBAC_STR+'Invalid Action')
            return 


    def check_permission(self,action):
        if action =='n':
            if self.permission[0]=='1':
                print (RBAC_STR+'User '+self.session_user_name+' Create File Successfully.')
            else:
                print (RBAC_STR+'Permission Denied: User '+self.session_user_name+' Does Not Have the Create Permission.')
            return 
        if action =='r':
            if self.permission[1]=='1':
                print (RBAC_STR+'User '+self.session_user_name+' Read File Successfully.')
            else:
                print (RBAC_STR+'Permission Denied: User '+self.session_user_name+' Does Not Have the Read Permission.')
            return 
        if action =='e':
            if self.permission[2]=='1':
                print (RBAC_STR+'User '+self.session_user_name+' Execute File Successfully.')
            else:
                print (RBAC_STR+'Permission Denied: User '+self.session_user_name+' Does Not Have the Execute Permission.')
            return 
        if action =='d':
            if self.permission[3]=='1':
                print (RBAC_STR+'User '+self.session_user_name+' Delete File Successfully.')
            else:
                print (RBAC_STR+'Permission Denied: User '+self.session_user_name+' Does Not Have the Delete Permission.')
            return 
        if action =='w':
            if self.permission[4]=='1':
                print (RBAC_STR+'User '+self.session_user_name+' Write File Successfully.')
            else:
                print (RBAC_STR+'Permission Denied: User '+self.session_user_name+' Does Not Have the Write Permission.')
            return 

    def permission_update(self,target_permission):
        p_permission=''
        for i in range (5):
            if target_permission[i]=='1' and self.permission[i]=='0':
                p_permission=p_permission+'1'
            if target_permission[i]=='1' and self.permission[i]=='1':
                p_permission=p_permission+'1'
            if target_permission[i]=='0' and self.permission[i]=='1':
                p_permission=p_permission+'1'
            if target_permission[i]=='0' and self.permission[i]=='0':
                p_permission=p_permission+'0'
        self.permission=str(p_permission)














