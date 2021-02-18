from session.session import *
from utils.db_operation import *


RBAC_STR='[RBAC] '

class User(object):
    def __init__(self,name,id):
        self.user_name=name
        self.user_id=id
        self.session_list=[]
        self.session_list_len=len(self.session_list)
        self.role_list=user_id2role_list(self.user_id)
        self.role_list_len=len(self.role_list)
        role_id2permission_id(id)

    def get_user_name(self):
        return str(self.user_name)

    def get_user_id(self):
        return str(self.user_id)

    def get_session_len(self):
        return len(self.session_list)

    def get_certain_session(self,idx):
        if idx>(self.get_session_len()):
            print (RBAC_STR+'Session Index '+str(idx)+' Out of Range.')
            return None
        else:
            return self.session_list[idx]

    def create_session(self):
        new_session=Session(self.user_name,self.role_list)
        self.session_list.append(new_session)
        self.session_list_len=len(self.session_list)
        print (RBAC_STR+'User '+self.user_name+' Create A New Session.')

    def show_roles(self):
        print (RBAC_STR+'Show Roles.')
        if self.role_list_len==0:
            print (RBAC_STR+'No Role.')
            return 
        for i in range (self.role_list_len):
            print (RBAC_STR+'{:15s}{:15s}{:15s}{:15s}'.format('role_id','role_name','role_rank','role_exlusion'))
            print (RBAC_STR+'{:15s}{:15s}{:15s}{:15s}'.format(str(self.role_list[i].get_id()),str(self.role_list[i].get_role_name()),str(self.role_list[i].get_rank()),str(self.role_list[i].get_exclussion())))

    def show_session(self):
        print (RBAC_STR+'Show Sessions.')
        if self.session_list_len==0:
            print (RBAC_STR+'No Session.')
            return 
        for i in range (self.session_list_len):
            print (RBAC_STR+'{:15s}{:15s}'.format('session_idx','session_permission'))
            print (RBAC_STR+'{:15s}{:15s}'.format(str(i),str(self.session_list[i].get_permission()),))

