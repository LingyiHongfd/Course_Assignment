import csv
import os
import pandas as pd
from utils.new_csv import *
from utils.db_operation import *
from utils.log import *
from user.user_class import *
from utils.user_utils import *

RBAC_STR='[RBAC] '

print (RBAC_STR+'User Mode.')
session=None
user=login()
if user==None:
    print (RBAC_STR+'User '+user_name+' does not exist')
else:
    print (RBAC_STR+'User '+user.get_user_name()+' Login Sucessfully!')

while (True):
    input_command=input(RBAC_STR+'>>> ')
    user,session=command(input_command,user,session)









