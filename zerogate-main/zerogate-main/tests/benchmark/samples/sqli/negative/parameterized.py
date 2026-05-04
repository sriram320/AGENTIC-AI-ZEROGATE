query = 'SELECT * FROM users WHERE id = ?'
cursor.execute(query, (req.query.id,))