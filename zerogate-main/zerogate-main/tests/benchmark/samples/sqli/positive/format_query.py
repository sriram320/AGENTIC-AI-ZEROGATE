query = 'SELECT * FROM users WHERE id = {}'.format(req.query.id)
cursor.execute(query)