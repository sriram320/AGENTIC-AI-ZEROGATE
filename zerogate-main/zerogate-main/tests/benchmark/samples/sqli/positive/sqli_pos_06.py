sql = 'SELECT * FROM secrets WHERE key = "' + user_id + '"'
db_session.execute(sql)