import csv
import os
import pandas as pd



def write_user():
    C={'user_name':['A','B','M1','C','D','M2','Boss'],
   'user_id':['1','2','3','4','5','6','7'],
    }
    df=pd.DataFrame(C,columns=['user_name','user_id'],)
    export_csv = df.to_csv (r'./database/user.csv', index = None, header=True) 

def write_user2role():
    C={'user_id':['1','2','3','4','5','6','7'],
   'role_id':['1','1','3','2','2','4','5']
    }
    df=pd.DataFrame(C,columns=['user_id','role_id'],)
    export_csv = df.to_csv (r'./database/user2role.csv', index = None, header=True) 


def write_role():
    C={'role_id':['1','2','3','4','5'],
   'role_name':['staff1r0e0','staff2r0e0','manager1r0e0','manager2r0e0','bossr0e0'],
   'rank':['r0','r0','r0','r0','r0'],
   'exclusion':['e0','e0','e0','e0','e0']
    }
    df=pd.DataFrame(C,columns=['role_id','role_name','rank','exclusion'],)
    export_csv = df.to_csv (r'./database/role.csv', index = None, header=True) 


def write_role2permission():
    C={'role_id':['1','2','3','4','5'],
   'permission_id':['1','2','3','4','5'],
    }
    df=pd.DataFrame(C,columns=['role_id','permission_id'],)
    export_csv = df.to_csv (r'./database/role2permission.csv', index = None, header=True) 

def write_permission():
    '''
    permission  0 for no  1  for have
    using just 0-1 string to demonstrate permission not like linux using number
    premission seq:
    create  read  execute  delete  write      
    '''
    C={'permission_id':['1','2','3','4','5'],
   'permission_label':['01100','01001','01110','10111','11111'],
    }
    df=pd.DataFrame(C,columns=['permission_id','permission_label'],)
    export_csv = df.to_csv (r'./database/permission.csv', index = None, header=True) 


