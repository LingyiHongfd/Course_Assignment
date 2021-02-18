import csv
import os
import pandas as pd
from utils.new_csv import *
from utils.db_operation import *
from utils.log import *
from user.user_class import *
from utils.admin_utils import *

RBAC_STR='[RBAC] '

print (RBAC_STR+'Admin Mode.')


while (True):
    input_command=input(RBAC_STR+'>>> ')
    command(input_command)








