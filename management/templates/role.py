# PUT /_security/role/sales_role
# {
#   "cluster": ["monitor"], 
#   "indices": [
#     {
#       "names": ["sales_data_*"], 
#       "privileges": ["read"]
#     }
#   ],
#   "applications": [
#     {
#       "application": "kibana-.kibana",
#       "privileges": ["read"],
#       "resources": ["dashboard/sales_*"]
#     }
#   ]
# }

# # 































































