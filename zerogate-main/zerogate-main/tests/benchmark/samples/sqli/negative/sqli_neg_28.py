uid = int(user_id)
db_session.execute(f'SELECT * FROM users WHERE id = {uid}')