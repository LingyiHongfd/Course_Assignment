

class Role(object):
    def __init__(self,id,role_name,rank,exclusion,permission):
        self.role_id=id
        self.role_name=role_name
        self.rank=rank
        self.exclusion=exclusion
        self.permission=permission

    def get_id(self):
        return self.role_id
    def get_role_name(self):
        return self.role_name
    def get_rank(self):
        return self.rank
    def get_exclussion(self):
        return self.exclusion
    def get_permission(self):
        return self.permission

