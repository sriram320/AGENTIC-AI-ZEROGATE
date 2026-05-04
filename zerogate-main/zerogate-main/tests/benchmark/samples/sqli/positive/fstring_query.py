query = f'SELECT * FROM users WHERE id = {req.query.id}'
cursor.execute(query)