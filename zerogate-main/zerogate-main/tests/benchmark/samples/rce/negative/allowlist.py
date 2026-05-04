import os
if req.query.ip in ['127.0.0.1']: os.system('ping ' + req.query.ip)