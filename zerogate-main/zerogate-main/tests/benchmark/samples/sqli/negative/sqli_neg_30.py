uid = int(data)
connection.execute(f'SELECT * FROM users WHERE id = {uid}')